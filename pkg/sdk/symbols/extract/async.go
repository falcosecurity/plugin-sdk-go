/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package extract

/*
#include "extract.h"
*/
import "C"
import (
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
)

const (
	state_wait = iota
	state_data_req
	state_exit_req
	state_exit_ack
)

const (
	starvationThresholdNs = int64(1e6)
	sleepTimeNs           = 1e7 * time.Nanosecond
)

var (
	// asyncEnabled is true if the async optimization is configured as enabled
	asyncEnabled bool = true
	//
	// asyncMutex ensures that StartAsync() and StopAsync are used in mutual
	// exclusion
	asyncMutex sync.Mutex
	//
	// asyncCount is incremented at every call to StartAsync() and
	// is decremented at every call to StopAsync()
	asyncCount int32 = 0
	//
	// asyncCtxBatch is a slice of async info contexts that is shared between
	// C and Go. Each batch slot contains a unique lock and is assigned to
	// only one cgo.Handle value.
	//
	// note(jasondellaluce): this is dependent on our internal implementation
	// of cgo.Handle. Since cgo.Handle values are regular integers between 1
	// and cgo.MaxHandle, they are used to assign the batch slot index to
	// each consumer. Each initialized plugin is a distinct consumer and has
	// its own assigned cgo.Handle value.
	// I don't like leaking this implementation knowledge of our cgo package,
	// however the goal here is to achieve maximum performance and using
	// array-based access is the best we can get.
	//
	// todo(jasondellaluce): change this if we change cgo.Handle implementation
	asyncCtxBatch []C.async_extractor_info
	//
	// asyncCtxBatchCap is the physical size of asyncCtxBatch as allocated
	// in C memory, namely the total number of slots available for consumers.
	asyncCtxBatchCap = cgo.MaxHandle + 1
	//
	// asyncCtxBatchLen is the number of occupied slots of asyncCtxBatch. This
	// value is >= 0 and < asyncCtxBatchCap. The solely purpose of
	// counting the number of occupied lock slots is for the worker to avoid
	// looping over the whole batch when only few slots are really used, which
	// is a big improvement in performance. This value is incremented at every
	// call to StartAsync(), and is never decremented. The reason is that the
	// value spaces for cgo.Handle can become sparse when a plugin is destroyed
	// and its cgo.Handle deleted. We can assume already-assigned cgo.Handles
	// to be reuased after deletion, but we can't make assumptions on which
	// is the largest cgo.Handle used in a given moment.
	asyncCtxBatchLen = uint32(0)
)

// SetAsync enables or disables the async extraction optimization depending
// on the passed-in boolean. Note, setting the optimization as enabled does not
// guarantee that it will be used at runtime: the optimization will not
// be activated if the hardware configuration doesn't match the minimum requirements.
func SetAsync(enable bool) {
	asyncEnabled = enable
}

// Async returns true if the async extraction optimization is
// configured as enabled, and false otherwise.
func Async() bool {
	return asyncEnabled
}

// since the async worker can potentially keep a whole thread (and its CPU)
// busy on high workloads, we consider the optimization available only if
// we run on at least 2 CPUs.
func asyncAvailable() bool {
	// note: runtime.GOMAXPROCS(0) should be more accurate than runtime.NumCPU()
	// and and better aligns with the developer/user thread pool configuration.
	//
	// todo(jasondellaluce): changing runtime.GOMAXPROCS after starting the
	// async worker would break the plugin
	return runtime.GOMAXPROCS(0) > 1
}

func initAsyncCtxBatch() {
	// initialize the batch in C memory
	batch := unsafe.Pointer(C.async_init((C.size_t)(asyncCtxBatchCap)))

	// convert the batch into a Go slice
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtxBatch)).Data = uintptr(batch)
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtxBatch)).Len = int(asyncCtxBatchCap)
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtxBatch)).Cap = int(asyncCtxBatchCap)

	// initialize all the locks in the batch
	for i := 0; i < asyncCtxBatchCap; i++ {
		atomic.StoreInt32((*int32)(&asyncCtxBatch[i].lock), state_wait)
	}
}

func destroyAsyncCtxBatch() {
	asyncCtxBatch = nil
	atomic.StoreUint32(&asyncCtxBatchLen, 0)
	C.async_deinit()
}

func asyncWorker() {
	waitStartTime := time.Now().UnixNano()
	for {
		// check async context slots in round-robin
		for i := uint32(1); i < atomic.LoadUint32(&asyncCtxBatchLen)+1; i++ {
			// Check for incoming request, if any, otherwise busy waits
			switch atomic.LoadInt32((*int32)(&asyncCtxBatch[i].lock)) {

			case state_data_req:
				// Incoming data request. Process it...
				asyncCtxBatch[i].rc = C.int32_t(
					plugin_extract_fields_sync(
						C.uintptr_t(uintptr(asyncCtxBatch[i].s)),
						asyncCtxBatch[i].evt,
						uint32(asyncCtxBatch[i].num_fields),
						asyncCtxBatch[i].fields,
					),
				)
				// Processing done, return back to waiting state
				atomic.StoreInt32((*int32)(&asyncCtxBatch[i].lock), state_wait)
				// Reset waiting start time
				waitStartTime = 0

			case state_exit_req:
				// Incoming exit request. Send ack and exit.
				atomic.StoreInt32((*int32)(&asyncCtxBatch[i].lock), state_exit_ack)
				return
			}

			// busy wait, then sleep after 1ms
			if waitStartTime == 0 {
				waitStartTime = time.Now().UnixNano()
			} else if time.Now().UnixNano()-waitStartTime > starvationThresholdNs {
				time.Sleep(sleepTimeNs)
			}
		}
	}
}

func stopAsync() {
	for !atomic.CompareAndSwapInt32((*int32)(&asyncCtxBatch[1].lock), state_wait, state_exit_req) {
		// spin
	}

	// state_exit_req acquired, wait for worker exiting
	for atomic.LoadInt32((*int32)(&asyncCtxBatch[1].lock)) != state_exit_ack {
		// spin
	}
}

// StartAsync initializes and starts the asynchronous extraction mode.
// Once StartAsync has been called, StopAsync must be called before terminating
// the program. The number of calls to StartAsync and StopAsync must be equal
// in the program. Independently by the number of StartAsync/StopAsync calls,
// there will never be more than one async worker activated at the same time.
//
// This is a way to optimize field extraction for use cases in which the rate
// of calls to plugin_extract_fields() is considerably high, so that the
// overhead of the C -> Go calls may become unacceptable for performance.
// Asynchronous extraction solves this problem by launching a worker
// goroutine and by synchronizing with it through a spinlock.
// The worker implements a busy wait, in order to ensure that the scheduler
// sleeps it from its execution as less as possible. This is only suitable
// for multi-core architectures, and has a significant impact on CPU usage,
// so it should be carefully used only if the rate of C -> Go calls makes
// the tradeoff worth it.
//
// After calling StartAsync, the framework automatically shift the extraction
// strategy from the regular C -> Go call one to the alternative worker
// synchronization one.
func StartAsync() {
	asyncMutex.Lock()
	defer asyncMutex.Unlock()

	asyncCount += 1
	atomic.AddUint32(&asyncCtxBatchLen, 1)
	if !asyncAvailable() || !asyncEnabled || asyncCount > 1 {
		return
	}

	initAsyncCtxBatch()
	go asyncWorker()
}

// StopAsync deinitializes and stops the asynchronous extraction mode, and
// undoes a single StartAsync call. It is a run-time error if StartAsync was
// not called before calling StopAsync.
func StopAsync() {
	asyncMutex.Lock()
	defer asyncMutex.Unlock()

	asyncCount -= 1
	if asyncCount < 0 {
		panic("plugin-sdk-go/sdk/symbols/extract: async worker stopped without being started")
	}

	if asyncCount == 0 && asyncCtxBatch != nil {
		stopAsync()
		destroyAsyncCtxBatch()
	}
}
