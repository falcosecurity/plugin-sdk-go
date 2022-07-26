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

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

type sampleAsyncExtract struct {
	sampleExtract
	counter uint64
}

func (s *sampleAsyncExtract) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	req.SetValue(s.counter)
	s.counter++
	return nil
}

func testAllocAsyncBatch() []_Ctype_async_extractor_info {
	return make([]_Ctype_async_extractor_info, asyncBatchSize)
}

func testReleaseAsyncBatch(c []_Ctype_async_extractor_info) {}

func TestSetAsync(t *testing.T) {
	a := asyncContext{}
	if !a.Async() {
		t.Fatalf("Async returned %v but expected %v", false, true)
	}

	a.SetAsync(false)
	if a.Async() {
		t.Fatalf("Async returned %v but expected %v", true, false)
	}

	a.SetAsync(true)
	if !a.Async() {
		t.Fatalf("Async returned %v but expected %v", false, true)
	}
}

func TestAsyncGetMaxWorkers(t *testing.T) {
	a := asyncContext{}
	expected := []int32{0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5}
	for i, ex := range expected {
		v := a.getMaxWorkers(i + 1)
		if v != ex {
			t.Fatalf("getMaxWorkers returned %d but expected %d", v, ex)
		}
	}
}

func TestAsyncBatchIdxWorkerIdx(t *testing.T) {
	for maxWorkers := 1; maxWorkers < 100; maxWorkers++ {
		a := asyncContext{maxWorkers: int32(maxWorkers)}
		for i := int32(0); i < 10; i++ {
			if a.batchIdxToWorkerIdx(i) != i%a.maxWorkers {
				t.Fatalf("batchIdxToWorkerIdx returned %d but expected %d", a.batchIdxToWorkerIdx(i), i%a.maxWorkers)
			}
		}
		for i := int32(0); i < a.maxWorkers; i++ {
			expectedIdx := int32(i)
			for _, v := range a.workerIdxToBatchIdxs(i) {
				if v != expectedIdx {
					t.Fatalf("workerIdxToBatchIdxs returned %d but expected %d", v, expectedIdx)
				}
				expectedIdx += a.maxWorkers
			}
		}
	}
}

func testWithMockPlugins(n int, f func([]cgo.Handle)) {
	plugins := make([]sampleAsyncExtract, n)
	handles := make([]cgo.Handle, n)
	for i := 0; i < n; i++ {
		handles[i] = cgo.NewHandle(&plugins[i])
		plugins[i].SetExtractRequests(sdk.NewExtractRequestPool())
	}
	f(handles)
	for i := 0; i < n; i++ {
		handles[i].Delete()
		plugins[i].ExtractRequests().Free()
	}
}

// this simulates a C consumer as in extract.c
func testSimulateAsyncRequest(t testing.TB, a *asyncContext, h cgo.Handle, r *_Ctype_ss_plugin_extract_field) {
	i := a.handleToBatchIdx(h)
	a.batch[i].s = unsafe.Pointer(h)
	a.batch[i].evt = nil
	a.batch[i].num_fields = 1
	a.batch[i].fields = r

	atomic.StoreInt32((*int32)(&a.batch[i].lock), state_data_req)
	for atomic.LoadInt32((*int32)(&a.batch[i].lock)) != state_wait {
		// spin
	}
	if int32(a.batch[i].rc) != sdk.SSPluginSuccess {
		t.Fatalf("extraction failed with rc %v", int32(a.batch[i].rc))
	}
}

func TestAsyncExtract(t *testing.T) {
	a := asyncContext{}
	workload := func(nPlugins, nExtractions int) {
		testWithMockPlugins(nPlugins, func(handles []cgo.Handle) {
			var wg sync.WaitGroup
			for _, h := range handles {
				wg.Add(1)
				go func(h cgo.Handle) {
					counter := uint64(0)
					field, freeField := allocSSPluginExtractField(1, sdk.FieldTypeUint64, "", "")
					defer freeField()

					// note: StartAsync/StopAsync are not invoked concurrently
					// in the plugin framework, however we want to test them to
					// be thread-safe as they are designed
					a.StartAsync(h, testAllocAsyncBatch)
					for e := 0; e < nExtractions; e++ {
						testSimulateAsyncRequest(t, &a, h, field)
						value := **((**uint64)(unsafe.Pointer(&field.res[0])))
						if value != counter {
							panic(fmt.Sprintf("extracted %d but expected %d", value, counter))
						}
						counter++
					}
					a.StopAsync(h, testReleaseAsyncBatch)
					wg.Done()
				}(h)
			}
			wg.Wait()
		})
	}

	// run with increasing number of concurrent consumers
	for i := 1; i <= cgo.MaxHandle; i *= 2 {
		// run with increasing number of extractions
		for j := 1; j < 10000; j *= 10 {
			workload(i, j)
		}
	}
}

func TestStartStopAsync(t *testing.T) {
	nPlugins := cgo.MaxHandle
	testWithMockPlugins(nPlugins, func(handles []cgo.Handle) {
		// test unbalanced start/stop calls
		assertPanic(t, func() {
			a := asyncContext{}
			a.StopAsync(handles[0], testReleaseAsyncBatch)
		})
		assertPanic(t, func() {
			a := asyncContext{}
			a.StartAsync(handles[0], testAllocAsyncBatch)
			a.StopAsync(handles[0], testReleaseAsyncBatch)
			a.StopAsync(handles[0], testReleaseAsyncBatch)
		})

		// test with bad start/stop-handle pair
		assertPanic(t, func() {
			a := asyncContext{}
			a.StartAsync(handles[0], testAllocAsyncBatch)
			a.StartAsync(handles[1], testAllocAsyncBatch)
			a.StopAsync(handles[0], testReleaseAsyncBatch)
			a.StopAsync(handles[0], testReleaseAsyncBatch)
		})

		// test with inconsistent enabled values
		a := asyncContext{}
		enabled := true
		for i := 0; i < nPlugins; i++ {
			a.SetAsync(enabled)
			a.StartAsync(handles[i], testAllocAsyncBatch)
			enabled = !enabled
		}
		for i := 0; i < nPlugins; i++ {
			a.StopAsync(handles[i], testReleaseAsyncBatch)
		}

		// test workload after already having started/stopped the same context
		var wg sync.WaitGroup
		for _, h := range handles {
			wg.Add(1)
			a.StartAsync(h, testAllocAsyncBatch)
			go func(h cgo.Handle) {
				counter := uint64(0)
				field, freeField := allocSSPluginExtractField(1, sdk.FieldTypeUint64, "", "")
				defer freeField()
				for e := 0; e < 1000; e++ {
					testSimulateAsyncRequest(t, &a, h, field)
					value := **((**uint64)(unsafe.Pointer(&field.res[0])))
					if value != counter {
						panic(fmt.Sprintf("extracted %d but expected %d", value, counter))
					}
					counter++
				}
				wg.Done()
			}(h)
		}
		wg.Wait()
		for _, h := range handles {
			a.StopAsync(h, testReleaseAsyncBatch)
		}
	})
}
