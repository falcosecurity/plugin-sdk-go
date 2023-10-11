// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package asyncbench

import (
	"sync/atomic"
)

/*
#include "bench.h"
*/
import "C"

func benchmark_async(lock *int32, n int) {
	C.async_benchmark((*C.int32_t)(lock), C.int(n))
}

func benchmark_sync(n int, input int) {
	C.sync_benchmark(C.int(n), C.int(input))
}

const (
	state_wait = iota
	state_data_req
	state_exit_req
	state_exit_ack
)

func startWorker(lock *int32) {
	go func() {
		for {
			// Check for incoming request, if any, otherwise busy waits
			switch atomic.LoadInt32(lock) {

			case state_data_req:
				// Incoming data request. Process it...
				outData = doWork(inData)
				// Processing done, return back to waiting state
				atomic.StoreInt32(lock, state_wait)

			case state_exit_req:
				// Incoming exit request. Send ack and exit.
				atomic.StoreInt32(lock, state_exit_ack)
				return

			default:
				// busy wait
			}
		}
	}()
}

func dataRequest(lock *int32) {
	// We assume state_wait because no concurrent requests are supported
	for !atomic.CompareAndSwapInt32(lock, state_wait, state_data_req) {
		// spin
	}

	// state_data_req acquired, wait for worker completation
	for atomic.LoadInt32(lock) != state_wait {
		// spin
	}
}

func exitRequest(lock *int32) {
	// We assume state_wait because no concurrent requests are supported
	for !atomic.CompareAndSwapInt32(lock, state_wait, state_exit_req) {
		// spin
	}

	// state_exit_req acquired, wait for worker exiting
	for atomic.LoadInt32(lock) != state_exit_ack {
		// spin
	}
}
