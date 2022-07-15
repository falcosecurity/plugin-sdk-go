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
	// todo(jasondellaluce): change this if we increase the max number of handles
	asyncCtxSize = cgo.MaxHandle + 1
)

var (
	asyncCtx     *C.async_extractor_info
	asyncMutex   sync.Mutex
	asyncEnabled bool  = true
	asyncCount   int32 = 0
)

func asyncAvailable() bool {
	return runtime.NumCPU() > 1
}

func SetAsync(enable bool) {
	asyncEnabled = enable
}

func Async() bool {
	return asyncEnabled
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
	if !asyncAvailable() || !asyncEnabled || asyncCount > 1 {
		return
	}

	// initialize async context slots
	var asyncCtx []C.async_extractor_info
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtx)).Data = uintptr(unsafe.Pointer(C.async_init((C.size_t)(asyncCtxSize))))
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtx)).Len = int(asyncCtxSize)
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtx)).Cap = int(asyncCtxSize)
	for i := 0; i < asyncCtxSize; i++ {
		atomic.StoreInt32((*int32)(&asyncCtx[i].lock), state_wait)
	}
	go func() {
		waitStartTime := time.Now().UnixNano()
		for {
			// check async context slots in round-robin
			for i := 0; i < asyncCtxSize; i++ {
				// Check for incoming request, if any, otherwise busy waits
				switch atomic.LoadInt32((*int32)(&asyncCtx[i].lock)) {

				case state_data_req:
					// Incoming data request. Process it...
					asyncCtx[i].rc = C.int32_t(
						plugin_extract_fields_sync(
							C.uintptr_t(uintptr(asyncCtx[i].s)),
							asyncCtx[i].evt,
							uint32(asyncCtx[i].num_fields),
							asyncCtx[i].fields,
						),
					)
					// Processing done, return back to waiting state
					atomic.StoreInt32((*int32)(&asyncCtx[i].lock), state_wait)
					// Reset waiting start time
					waitStartTime = 0

				case state_exit_req:
					// Incoming exit request. Send ack and exit.
					atomic.StoreInt32((*int32)(&asyncCtx[i].lock), state_exit_ack)
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
	}()
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

	if asyncCount == 0 && asyncCtx != nil {
		lock := (*int32)(&asyncCtx.lock)

		for !atomic.CompareAndSwapInt32(lock, state_wait, state_exit_req) {
			// spin
		}

		// state_exit_req acquired, wait for worker exiting
		for atomic.LoadInt32(lock) != state_exit_ack {
			// spin
		}
		asyncCtx = nil
		C.async_deinit()
	}
}
