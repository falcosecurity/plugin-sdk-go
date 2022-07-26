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
	"math"
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
	// asyncBatchSize is the physical size of batches allocated
	// in C memory, namely the total number of locks available
	asyncBatchSize = cgo.MaxHandle + 1
)

var (
	// ctx is the asyncContext instance used by the SDK
	ctx asyncContext
)

// asyncContext bundles all the state information used by the async
// extraction optimization
type asyncContext struct {
	// disabled is false if the async optimization is configured
	// to be enabled
	disabled bool
	//
	// available if the underlying hardware configuration supports the
	// async optimization
	available bool
	//
	// m ensures that Async/SetAsync/StartAsync/StopAsync are invoked
	// with mutual exclusion
	m sync.Mutex
	//
	// count is incremented at every call to StartAsync and
	// is decremented at every call to StopAsync
	count int32
	//
	// batch is a batch of info that is shared between C and Go.
	// Each slot of the batch contains a distinct lock and is assigned
	// to only one cgo.Handle value.
	batch []C.async_extractor_info
	//
	// maxWorkers is the max number of workers that can be active at the same time
	maxWorkers int32
	//
	// activeWorkers entries are true if an async worker is currently active
	// at the given index. The size of activeWorkers is maxWorkers.
	activeWorkers []bool
	//
	// maxBatchIdx is the greatest slot index occupied in the batch.
	// This value is >= 0 and < asyncCtxBatchCap. This is used by async workers
	// to avoid looping over batch slots that are known to be unused in order to
	// minimize the synchronization overhead.
	maxBatchIdx int32
}

func (a *asyncContext) SetAsync(enable bool) {
	a.m.Lock()
	defer a.m.Unlock()
	a.disabled = !enable
}

func (a *asyncContext) Async() bool {
	a.m.Lock()
	defer a.m.Unlock()
	return !a.disabled
}

// 1 batch slot maps to only 1 worker
func (a *asyncContext) batchIdxToWorkerIdx(slotIdx int32) int32 {
	return slotIdx % a.maxWorkers
}

// 1 worker maps to 1+ batch slots
func (a *asyncContext) workerIdxToBatchIdxs(workerIdx int32) (res []int32) {
	for i := int32(workerIdx); i < int32(asyncBatchSize); i += a.maxWorkers {
		res = append(res, i)
	}
	return
}

func (a *asyncContext) handleToBatchIdx(h cgo.Handle) int32 {
	return int32(h) - 1
}

func (a *asyncContext) getMaxWorkers(maxProcs int) int32 {
	return int32(math.Ceil(math.Log2(float64(maxProcs))))
}

func (a *asyncContext) acquireWorker(workerIdx int32) {
	if a.activeWorkers[workerIdx] {
		// worker is already running
		return
	}

	// start the worker
	a.activeWorkers[workerIdx] = true
	go func() {
		waitStartTime := time.Now().UnixNano()
		batchIdxs := a.workerIdxToBatchIdxs(workerIdx)
		for {
			// loop over async context batch slots in round-robin
			for _, i := range batchIdxs {
				// reduce sync overhead by skipping unused batch slots
				if i > a.maxBatchIdx {
					continue
				}

				// check for incoming request, if any, otherwise busy waits
				switch atomic.LoadInt32((*int32)(&a.batch[i].lock)) {

				case state_data_req:
					// incoming data request, process it...
					a.batch[i].rc = C.int32_t(
						plugin_extract_fields_sync(
							C.uintptr_t(uintptr(a.batch[i].s)),
							a.batch[i].evt,
							uint32(a.batch[i].num_fields),
							a.batch[i].fields,
						),
					)
					// processing done, return back to waiting state
					atomic.StoreInt32((*int32)(&a.batch[i].lock), state_wait)
					// reset waiting start time
					waitStartTime = 0

				case state_exit_req:
					// Incoming exit request. Send ack and exit.
					atomic.StoreInt32((*int32)(&a.batch[i].lock), state_exit_ack)
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

func (a *asyncContext) releaseWorker(workerIdx int32) {
	if !a.activeWorkers[workerIdx] {
		// work is not running, no need to stop it
		return
	}

	// check all the batch slots assigned to the worker,
	// and stop it only if all of them are unused
	for _, i := range a.workerIdxToBatchIdxs(workerIdx) {
		if atomic.LoadInt32((*int32)(&a.batch[i].lock)) != state_unused {
			// worker is still needed, we should not stop it
			return
		}
	}

	// at this point, all slots assigned to the worker are
	// unused and the worker is looping over unused locks. Right from the Go
	// side, we use the first visible slot and set an exit request. The worker
	// will eventually synchronize with the used lock and stop.
	idx := a.workerIdxToBatchIdxs(workerIdx)[0]
	for !atomic.CompareAndSwapInt32((*int32)(&a.batch[idx].lock), state_unused, state_exit_req) {
		// spin
	}

	// wait for worker exiting
	for atomic.LoadInt32((*int32)(&a.batch[idx].lock)) != state_exit_ack {
		// spin
	}

	// restore first worker slot
	atomic.StoreInt32((*int32)(&a.batch[idx].lock), state_unused)
	a.activeWorkers[workerIdx] = false
}

func (a *asyncContext) StartAsync(handle cgo.Handle, allocBatch func() []C.async_extractor_info) {
	a.m.Lock()
	defer a.m.Unlock()

	a.count += 1

	// at the first StartAsync call, we check if the optimization is supported
	if a.count == 1 {
		// since on high workloads an async worker can potentially occupy a whole
		// thread (and its CPU), we consider the optimization available only if
		// we run on at least 2 CPUs.
		//
		// note: runtime.GOMAXPROCS(0) should be more accurate than
		// runtime.NumCPU() and and better aligns with the developer/user
		// thread pool configuration.
		a.available = runtime.GOMAXPROCS(0) > 1
	}

	// do nothing if the optimization can't be started
	if !a.available || a.disabled {
		return
	}

	// init the context when the first consumer starts the async optimization
	if a.count >= 1 && a.batch == nil {
		// init a new batch
		a.batch = allocBatch()
		for i := 0; i < asyncBatchSize; i++ {
			atomic.StoreInt32((*int32)(&a.batch[i].lock), state_unused)
		}

		// no batch index is used at the beginning
		atomic.StoreInt32(&a.maxBatchIdx, 0)

		// compute the max number of workers and set all of them as unused
		a.maxWorkers = a.getMaxWorkers(runtime.GOMAXPROCS(0))
		a.activeWorkers = make([]bool, a.maxWorkers)
	}

	// assign a batch slot to this handle and acquire a worker.
	// Each handle has a 1-1 mapping with a batch slot
	batchIdx := a.handleToBatchIdx(handle)
	atomic.StoreInt32((*int32)(&a.batch[batchIdx].lock), state_wait)
	if batchIdx > atomic.LoadInt32(&a.maxBatchIdx) {
		atomic.StoreInt32(&a.maxBatchIdx, batchIdx)
	}
	a.acquireWorker(a.batchIdxToWorkerIdx(batchIdx))
}

func (a *asyncContext) StopAsync(handle cgo.Handle, freeBatch func([]C.async_extractor_info)) {
	a.m.Lock()
	defer a.m.Unlock()

	a.count -= 1
	if a.count < 0 {
		panic("plugin-sdk-go/sdk/symbols/extract: async worker stopped without being started")
	}

	if a.batch != nil {
		// update the state vars if this handle used async extraction
		batchIdx := a.handleToBatchIdx(handle)
		if atomic.LoadInt32((*int32)(&a.batch[batchIdx].lock)) != state_unused {
			// set the assigned batch slot as unused and release worker
			atomic.StoreInt32((*int32)(&a.batch[batchIdx].lock), state_unused)
			a.releaseWorker(a.batchIdxToWorkerIdx(batchIdx))

			// update the current maximum used slot, so that async workers
			// will not try to sync over this index
			if batchIdx == atomic.LoadInt32(&a.maxBatchIdx) {
				for i := int32(batchIdx) - 1; i >= 0; i-- {
					if atomic.LoadInt32((*int32)(&a.batch[i].lock)) != state_unused {
						atomic.StoreInt32(&a.maxBatchIdx, i)
						break
					}
				}
			}
		}

		// if this was the last handle to be destroyed,
		// then we can safely destroy the batch too
		if a.count == 0 {
			// all workers should already be stopped by now
			for i := int32(0); i < a.maxWorkers; i++ {
				if a.activeWorkers[i] {
					panic(fmt.Sprintf("plugin-sdk-go/sdk/symbols/extract: worker %d can't be stopped", i))
				}
			}
			freeBatch(a.batch)
			a.batch = nil
		}
	}
}

func allocBatchInCMemory() (res []C.async_extractor_info) {
	cBuf := unsafe.Pointer(C.async_init((C.size_t)(asyncBatchSize)))
	(*reflect.SliceHeader)(unsafe.Pointer(&res)).Data = uintptr(cBuf)
	(*reflect.SliceHeader)(unsafe.Pointer(&res)).Len = int(asyncBatchSize)
	(*reflect.SliceHeader)(unsafe.Pointer(&res)).Cap = int(asyncBatchSize)
	return
}

func freeBatchInCMemory(c []C.async_extractor_info) {
	C.async_deinit()
}

// SetAsync enables or disables the async extraction optimization depending
// on the passed-in boolean.
//
// Note, setting the optimization as enabled does not guarantee that it will
// be actually used at runtime, as the SDK will first check whether the hardware
// configuration matches some minimum requirements.
func SetAsync(enable bool) {
	ctx.SetAsync(enable)
}

// Async returns true if the async extraction optimization is
// configured to be enabled, and false otherwise. This is true by default.
func Async() bool {
	return ctx.Async()
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
// the underlying runtime capacity, otherwise this will have no effect.
// After calling StartAsync with SetAsync set to true, the framework will try to
// automatically shift the extraction strategy from the regular C -> Go call
// one to the alternative worker synchronization one.
//
// Note, StartAsync first checks the value of runtime.GOMAXPROCS(0) to detect
// if the underlying Go runtime is capable of supporting the async optimization.
// After the first call to StartAsync, changing the value of runtime.GOMAXPROCS
// has no effect on the async workers until undone with the respecting
// StopAsync call. As such, descreasing runtime.GOMAXPROCS is generally unsafe
// StartAsync and StopAsync calls because the optimization can eccessively
// occupy the downsized Go runtime and eventually block it.
func StartAsync(handle cgo.Handle) {
	ctx.StartAsync(handle, allocBatchInCMemory)
}

// StopAsync deinitializes the asynchronous extraction mode for the given plugin
// handle, and undoes a single previous StartAsync call. It is a run-time error
// if StartAsync was not called before calling StopAsync.
func StopAsync(handle cgo.Handle) {
	ctx.StopAsync(handle, freeBatchInCMemory)
}
