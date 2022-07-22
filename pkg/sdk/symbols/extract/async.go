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
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
)

//
// The code below implements of the async extraction optimization.
// Our goal is to defeat the C -> Go calls overhead and achieve better
// performance during the field extraction path, which is one of the hottest
// of in the plugin framework.
//
// The design follows the P3-S4 solution documented in the discussion of
// https://github.com/falcosecurity/plugin-sdk-go/issues/62.
// We have N concurrent consumers from the C world, N locks shared between C
// and Go, and M async workers in the Go world. The shared spinlocks are the
// point of synchronization between the C consumers and the Go workers.
// There is a 1-1 mapping between a C consumer and a shared lock, so there
// are no collisions between consumers on the same lock. As such, each consumer
// will be served always by the same one worker. On the countrary, each worker
// synchronizes with 1+ locks (and consumers), with a given rotation policy.
// The number of workers M, is not necessarily correlated con the number
// of consumers N. Note, each worker heavily occupies the CPU for small time
// bursts so M should be less than runtime.GOMAXPROCS.
//
// Each worker has an integer index and will just loop over slots at positions
// at (workerIndex + maxWorkers * i). This ensures that multiple async workers
// never collide trying to sync on the same slot.
// For example, assuming a maximum number of 3 workers:
//   - Worker 0 will sync over batch slots: 0, 3, 6, 9, ...
//   - Worker 1 will sync over batch slots: 1, 4, 7, 10, ...
//   - Worker 2 will sync over batch slots: 2, 5, 8, 11, ...
//
// note: this package is aware and dependent on the current implementation
// of our cgo package. Since cgo.Handle values are regular integers between 1
// and cgo.MaxHandle, they are used to assign the batch slot index to
// each consumer. Each initialized plugin is a distinct consumer and has
// its own assigned cgo.Handle value. I really don't like leaking this
// implementation knowledge of our cgo package, however the goal here is to
// reach maximum performance and using array-based access is our best option.
//
// todo(jasondellaluce): change this and extract.c if we change the current
// cgo.Handle implementation

const (
	state_unused   = iota // the lock is unused
	state_wait            // the lock is free and a new request can be sent
	state_data_req        // an extraction request has been sent by the consumer
	state_exit_req        // an exit request has been sent by the consumer
	state_exit_ack        // an exit request has been resolved by the worker
)

const (
	// starvationThresholdNs is the time in nanoseconds on which async workers
	// can be in busy-loop without going to sleep
	starvationThresholdNs = int64(1e6)
	//
	// sleepTimeNs is the sleep time in nanoseconds for async workers
	// after busy-looping for starvationThresholdNs time
	sleepTimeNs = 1e7 * time.Nanosecond
	//
	// asyncCtxBatchCap is the physical size of asyncCtxBatch as allocated
	// in C memory, namely the total number of locks available
	asyncCtxBatchCap = cgo.MaxHandle + 1
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
	// C and Go. Each slot of the batch contains a distinct lock and is assigned
	// to only one cgo.Handle value.
	//
	asyncCtxBatch []C.async_extractor_info
	//
	// activeWorkers entries are true if an async worker is currently active
	// at the given index. The size of activeWorkers is maxWorkers.
	activeWorkers = [maxWorkers]bool{}
	//
	// maxBatchIdx is the greatest slot index occupied in the batch.
	// This value is >= 0 and < asyncCtxBatchCap. This is used by async workers
	// to avoid looping over batch slots that are known to be unused in order to
	// minimize the synchronization overhead.
	maxBatchIdx = int32(0)
)

// maxWorkers is the max number of workers that can be active at the same time
// TODO: make this configurable and thread-safe
const maxWorkers = int32(3)

// SetAsync enables or disables the async extraction optimization depending
// on the passed-in boolean.
//
// Note, setting the optimization as enabled does not guarantee that it will
// be actually used at runtime, as the SDK will first check whether the hardware
// configuration matches some minimum requirements.
func SetAsync(enable bool) {
	// TODO: is it ok to call this at every plugin_init()?
	asyncEnabled = enable
}

// Async returns true if the async extraction optimization is
// configured to be enabled, and false otherwise.
func Async() bool {
	return asyncEnabled
}

// since on high workloads an async worker can potentially occupy a whole
// thread (and its CPU), we consider the optimization available only if
// we run on at least 2 CPUs.
func asyncAvailable() bool {
	// note: runtime.GOMAXPROCS(0) should be more accurate than runtime.NumCPU()
	// and and better aligns with the developer/user thread pool configuration.
	//
	// TODO: how do we prevent the plugin from breaking if
	// runtime.GOMAXPROCS(0) is changed after starting the async workers?
	// IDEA: make this a var boolean and set this while initializing the batch
	return runtime.GOMAXPROCS(0) > 1
}

func initAsyncCtxBatch() {
	// initialize the batch in C memory and convert the batch into a Go slice
	batch := unsafe.Pointer(C.async_init((C.size_t)(asyncCtxBatchCap)))
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtxBatch)).Data = uintptr(batch)
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtxBatch)).Len = int(asyncCtxBatchCap)
	(*reflect.SliceHeader)(unsafe.Pointer(&asyncCtxBatch)).Cap = int(asyncCtxBatchCap)

	// initialize all the locks in the batch as unused for now
	for i := 0; i < asyncCtxBatchCap; i++ {
		atomic.StoreInt32((*int32)(&asyncCtxBatch[i].lock), state_unused)
	}

	// no worker is active at the beginning
	for i := int32(0); i < maxWorkers; i++ {
		activeWorkers[i] = false
	}

	// no batch index is used at the beginning
	atomic.StoreInt32(&maxBatchIdx, 0)
}

func destroyAsyncCtxBatch() {
	asyncCtxBatch = nil
	C.async_deinit()
}

// 1 batch slot maps to only 1 worker
func batchIdxToWorkerIdx(slotIdx int32) int32 {
	return slotIdx % maxWorkers
}

// 1 worker maps to 1+ batch slots
func workerIdxToBatchIdxs(workerIdx int32) []int32 {
	var res []int32
	for i := int32(workerIdx); i < int32(asyncCtxBatchCap); i += maxWorkers {
		res = append(res, i)
	}
	return res
}

func handleToBatchIdx(h cgo.Handle) int32 {
	return int32(h) - 1
}

func startWorker(workerIdx int32) {
	waitStartTime := time.Now().UnixNano()
	batchIdxs := workerIdxToBatchIdxs(workerIdx)
	for {
		// ;oop over async context batch slots in round-robin
		for _, i := range batchIdxs {
			// reduce sync overhead by skipping unused batch slots
			if i > maxBatchIdx {
				continue
			}

			// check for incoming request, if any, otherwise busy waits
			switch atomic.LoadInt32((*int32)(&asyncCtxBatch[i].lock)) {

			case state_data_req:
				// incoming data request, process it...
				asyncCtxBatch[i].rc = C.int32_t(
					plugin_extract_fields_sync(
						C.uintptr_t(uintptr(asyncCtxBatch[i].s)),
						asyncCtxBatch[i].evt,
						uint32(asyncCtxBatch[i].num_fields),
						asyncCtxBatch[i].fields,
					),
				)
				// processing done, return back to waiting state
				atomic.StoreInt32((*int32)(&asyncCtxBatch[i].lock), state_wait)
				// reset waiting start time
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

// note: this has to be called only if all the batch slots visible to a worker
// are currently unused. So, we make a stop request from the Go side on the
// first used slot visible by the given worker. The worker will stop after
// resolving the first exit request.
func stopWorker(workerIdx int32) {
	if activeWorkers[workerIdx] {
		idx := workerIdxToBatchIdxs(workerIdx)[0]
		for !atomic.CompareAndSwapInt32((*int32)(&asyncCtxBatch[idx].lock), state_unused, state_exit_req) {
			// spin
		}

		// state_exit_req acquired, wait for worker exiting
		for atomic.LoadInt32((*int32)(&asyncCtxBatch[idx].lock)) != state_exit_ack {
			// spin
		}

		activeWorkers[workerIdx] = false
		return
	}
}

// StartAsync initializes and starts the asynchronous extraction mode for the
// given plugin handle. Once StartAsync has been called, StopAsync must be
// called before terminating the program. The number of calls to StartAsync
// and StopAsync must be equal in the program.
//
// This is a way to optimize field extraction for use cases in which the rate
// of calls to plugin_extract_fields() is considerably high, so that the
// overhead of the C -> Go calls may become unacceptable for performance.
// Asynchronous extraction solves this problem by launching worker
// goroutines and by synchronizing with them through shared spinlocks.
// Each worker implements a busy wait, in order to ensure that the scheduler
// sleeps it from its execution as less as possible. This is only suitable
// for multi-core architectures, and has a significant impact on CPU usage,
// so it should be carefully used only if the rate of C -> Go calls makes
// the tradeoff worth it.
//
// The behavior of StartAsync is influenced by the value set through SetAsync:
// if set to true the SDK will attempt to run the optimization depending on
// the underlying hardware capacity, otherwise this will have no effect.
// After calling StartAsync with SetAsync set to true, the framework will try to
// automatically shift the extraction strategy from the regular C -> Go call
// one to the alternative worker synchronization one.
func StartAsync(handle cgo.Handle) {
	asyncMutex.Lock()
	defer asyncMutex.Unlock()

	asyncCount += 1
	if !asyncAvailable() || !asyncEnabled {
		return
	}

	// init the batch if we haven't already
	if asyncCount >= 1 && asyncCtxBatch == nil {
		initAsyncCtxBatch()
	}

	// assign a batch slot to this handle
	// each handle has a 1-1 mapping with a batch slot
	batchIdx := handleToBatchIdx(handle)
	atomic.StoreInt32((*int32)(&asyncCtxBatch[batchIdx].lock), state_wait)
	if batchIdx > atomic.LoadInt32(&maxBatchIdx) {
		atomic.StoreInt32(&maxBatchIdx, batchIdx)
	}

	// spawn a worker for this handle, if not already active
	workerIdx := batchIdxToWorkerIdx(batchIdx)
	if !activeWorkers[workerIdx] {
		go startWorker(workerIdx)
		activeWorkers[workerIdx] = true
	}
}

// StopAsync deinitializes the asynchronous extraction mode for the given plugin
// handle, and undoes a single previous StartAsync call. It is a run-time error
// if StartAsync was not called before calling StopAsync.
func StopAsync(handle cgo.Handle) {
	asyncMutex.Lock()
	defer asyncMutex.Unlock()

	asyncCount -= 1
	if asyncCount < 0 {
		panic("plugin-sdk-go/sdk/symbols/extract: async worker stopped without being started")
	}

	if asyncCtxBatch != nil {
		// update the state vars if this handle used async extraction
		batchIdx := handleToBatchIdx(handle)
		if atomic.LoadInt32((*int32)(&asyncCtxBatch[batchIdx].lock)) != state_unused {
			// set the assigned batch slot as unused
			atomic.StoreInt32((*int32)(&asyncCtxBatch[batchIdx].lock), state_unused)

			// check all the batch slots assigned to the worker,
			// and stop it if all of them are unused
			workerNeeded := false
			workerIdx := batchIdxToWorkerIdx(batchIdx)
			for _, i := range workerIdxToBatchIdxs(workerIdx) {
				if atomic.LoadInt32((*int32)(&asyncCtxBatch[i].lock)) != state_unused {
					workerNeeded = true
					break
				}
			}
			if !workerNeeded {
				stopWorker(workerIdx)
			}

			// update the current maximum used slot, so that async workers
			// will not try to sync over this index
			if batchIdx == atomic.LoadInt32(&maxBatchIdx) {
				for i := int32(batchIdx) - 1; i >= 0; i-- {
					if atomic.LoadInt32((*int32)(&asyncCtxBatch[i].lock)) != state_unused {
						atomic.StoreInt32(&maxBatchIdx, i)
						break
					}
				}
			}
		}

		// if this was the last handle to be destroyed,
		// then we can safely destroy the batch too
		if asyncCount == 0 {
			// all workers should already be stopped by now
			for i := int32(0); i < maxWorkers; i++ {
				if activeWorkers[i] {
					panic(fmt.Sprintf("plugin-sdk-go/sdk/symbols/extract: worker %d can't be stopped", i))
				}
			}
			destroyAsyncCtxBatch()
		}
	}
}
