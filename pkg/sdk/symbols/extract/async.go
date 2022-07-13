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
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	state_idle = iota
	state_wait
	state_req_data
	state_ack_data
	state_req_exit
	state_ack_exit
)

const (
	starvationThresholdNs = int64(1e6)
	sleepTimeNs           = 1e7 * time.Nanosecond
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

	asyncCtx = C.async_init()
	atomic.StoreInt32((*int32)(&asyncCtx.lock), state_idle)
	go func() {
		lock := (*int32)(&asyncCtx.lock)
		waitStartTime := time.Now().UnixNano()

		for {
			// Check for incoming request, if any, otherwise busy waits
			switch atomic.LoadInt32(lock) {

			case state_req_data:
				// Incoming data request. Process it...
				asyncCtx.rc = C.int32_t(
					plugin_extract_fields_sync(
						C.uintptr_t(uintptr(asyncCtx.s)),
						asyncCtx.evt,
						uint32(asyncCtx.num_fields),
						asyncCtx.fields,
					),
				)
				// Processing done, return back to waiting state
				atomic.StoreInt32(lock, state_ack_data)
				// Reset waiting start time
				waitStartTime = 0

			case state_req_exit:
				// Incoming exit request. Send ack and exit.
				atomic.StoreInt32(lock, state_ack_exit)
				return

			default:
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

		// wait until worker accepts our request (just like we would do from
		// a C consumer)
		for !atomic.CompareAndSwapInt32(lock, state_idle, state_wait) {
			// spin
		}

		// send exit request
		atomic.StoreInt32(lock, state_req_exit)

		// busy-wait until worker completation
		for atomic.LoadInt32(lock) != state_ack_exit {
			// spin
		}

		// free-up worker (for consistency, since it probably already exited)
		atomic.StoreInt32(lock, state_idle)

		// de-initialize worker context
		asyncCtx = nil
		C.async_deinit()
	}
}
