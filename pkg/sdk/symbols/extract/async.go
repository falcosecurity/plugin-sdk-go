/*
Copyright (C) 2022 The Falco Authors.

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
	"math"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
)

// note: this package is aware and dependent on the current implementation
// of our cgo package. See doc comment of asyncCtxBatch for more context.
// todo(jasondellaluce): change this (and extract.c) if we change the
// current cgo.Handle implementation

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
	// asyncEnabled is true if the async optimization is configured
	// to be enabled
	asyncEnabled bool = true
	//
	// asyncMutex ensures that StartAsync and StopAsync are used with mutual
	// exclusion
	asyncMutex sync.Mutex
	//
	// asyncCount is incremented at every call to StartAsync and
	// is decremented at every call to StopAsync
	asyncCount int32 = 0
	//
	// asyncCtxBatch is a batch of async info contexts that is shared between
	// C and Go. Each slot of the batch contains a unique lock and is assigned
	// to only one cgo.Handle value.
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
	asyncCtxBatch []C.async_extractor_info
	//
	// asyncCtxBatchCap is the physical size of asyncCtxBatch as allocated
	// in C memory, namely the total number of slots available
	asyncCtxBatchCap = cgo.MaxHandle + 1
	//
	// asyncCtxBatchLen is the number of occupied slots of asyncCtxBatch.
	// This value is >= 0 and < asyncCtxBatchCap. The solely purpose of
	// counting the number of occupied lock slots is for the worker to avoid
	// looping over the whole batch when only few slots are really used, so that
	// the synchronization overhead is minimized in that point.
	// This value is incremented at every call to StartAsync and is
	// never decremented. The reason is that the value spaces for cgo.Handle
	// can become sparse when a plugin is destroyed and its cgo.Handle deleted.
	// We can assume already-assigned cgo.Handles to be reused after deletion,
	// but we can't make assumptions on which is the largest cgo.Handle used in
	// a given moment, so we have to loop and synchronize up until the
	// highest-index slot. This is set to zero at the last call to StopAsync
	// right after all the async workers are stopped.
	asyncCtxBatchLen = int32(0)
)

// TODO: make this configurable and thread-safe
const maxWorkers = int32(6)

// since on high workloads an async worker can potentially occupy a whole
// thread (and its CPU), we consider the optimization available only if
// we run on at least 2 CPUs.
func asyncAvailable() bool {
	// note: runtime.GOMAXPROCS(0) should be more accurate than runtime.NumCPU()
	// and and better aligns with the developer/user thread pool configuration.
	//
	// TODO: how do we prevent the plugin from breaking if
	// runtime.GOMAXPROCS(0) is changed after starting the async workers?
	return runtime.GOMAXPROCS(0) > 1
}

// SetAsync enables or disables the async extraction optimization depending
// on the passed-in boolean.
//
// Note, setting the optimization as enabled does
// not guarantee that it will be used at runtime, as the SDK will first check
// if the hardware configuration matches the minimum requirements.
func SetAsync(enable bool) {
	// TODO: is it ok to call this at every plugin_init()?
	asyncEnabled = enable
}

// Async returns true if the async extraction optimization is
// configured to be enabled, and false otherwise.
func Async() bool {
	return asyncEnabled
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
	atomic.StoreInt32(&asyncCtxBatchLen, 0)
	C.async_deinit()
}

func startWorker(workerIdx int32) {
	waitStartTime := time.Now().UnixNano()
	for {
		// Loop over async context batch slots in round-robin.
		//
		// Note: workers are assigned an integer index and will just loop
		// over slots at positions at (workerIndex + maxWorkers * i). This
		// ensures that multiple async workers never collide trying to sync
		// on the same slot. To prevent starvation on all slots, a new async
		// worker is spawned every time a new slot gets used up until the
		// max number of workers. Then, workers are not stopped until all the
		// slots become unused, which happens at the last call to StopAsync.
		// The logic is similar to the one documented for asyncCtxBatchLen.
		//
		// For example, assuming a maximum number of 3 workers:
		//   - Worker 0 will sync over slots: 0, 3, 6, 9, ...
		//   - Worker 1 will sync over slots: 1, 4, 7, 10, ...
		//   - Worker 2 will sync over slots: 2, 5, 8, 11, ...
		for i := int32(workerIdx); i < atomic.LoadInt32(&asyncCtxBatchLen); i += maxWorkers {
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

// note: this is called only at the last call to StopAsync, so it's safe to
// assume that all the batch slots are unused (in wait state). So, we make a
// stop request from the Go side on the first slot visible by the given worker.
// The worker will stop after resolving the first exit request.
func stopWorker(workerIdx int32) {
	for !atomic.CompareAndSwapInt32((*int32)(&asyncCtxBatch[workerIdx].lock), state_wait, state_exit_req) {
		// spin
	}

	// state_exit_req acquired, wait for worker exiting
	for atomic.LoadInt32((*int32)(&asyncCtxBatch[workerIdx].lock)) != state_exit_ack {
		// spin
	}

	atomic.StoreInt32((*int32)(&asyncCtxBatch[workerIdx].lock), state_wait)
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
func StartAsync(handle cgo.Handle) {
	asyncMutex.Lock()
	defer asyncMutex.Unlock()

	asyncCount += 1
	println("start", asyncCount)
	if !asyncAvailable() || !asyncEnabled {
		return
	}

	if asyncCount == 1 {
		initAsyncCtxBatch()
	}

	// newBatchLen represents the number of batch slots currently used, which
	// also equals to the maximum cgo.Handle value assigned so far.
	// Since cgo.Handle values can be reused when a plugin is initialized and
	// then destroyed, newBatchLen is the max value between the currently-known
	// max cgo.Handle value (asyncCtxBatchLen) and the current one.
	newBatchLen := int32(math.Max(float64(handle), float64(atomic.LoadInt32(&asyncCtxBatchLen))))
	atomic.StoreInt32(&asyncCtxBatchLen, newBatchLen)

	// spawn a new async worker for each new batch slot used up until the max
	// possible number of workers
	if newBatchLen-1 < maxWorkers {
		// note: worker indexes are 0-based and the batch len is > 1 here
		go startWorker(newBatchLen - 1)
	}
}

// StopAsync deinitializes and stops the asynchronous extraction mode, and
// undoes a single StartAsync call. It is a run-time error if StartAsync was
// not called before calling StopAsync.
func StopAsync(handle cgo.Handle) {
	asyncMutex.Lock()
	defer asyncMutex.Unlock()

	asyncCount -= 1
	println("stop", asyncCount)
	if asyncCount < 0 {
		panic("plugin-sdk-go/sdk/symbols/extract: async worker stopped without being started")
	}

	if asyncCtxBatch != nil && asyncCount == 0 {
		for i := int32(0); i < maxWorkers && i < asyncCtxBatchLen; i++ {
			stopWorker(i)
		}
		destroyAsyncCtxBatch()
	}
}
