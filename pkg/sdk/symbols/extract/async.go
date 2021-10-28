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
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var asyncWorkerRunning bool

// StartAsync initializes and starts the asynchronous extraction mode.
// Once StartAsync has been called, StopAsync must be called before terminating
// the program. Multiple calls to StartAsync will cause a panic if StopAsync is
// not called previously.
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
func StartAsync(e sdk.Extractor) {
	if asyncWorkerRunning {
		panic("plugin-sdk-go/sdk/symbols/extract: async worker already started")
	}
	asyncWorkerRunning = true
	info := C.create_async_extractor()
	go func() {
		extrReqs := e.(sdk.ExtractRequests)
		var extrReq sdk.ExtractRequest
		var field *C.struct_ss_plugin_extract_field
		var event *C.struct_ss_plugin_event
		for C.async_extractor_wait(info) {
			info.rc = C.int32_t(sdk.SSPluginSuccess)
			event = (*C.struct_ss_plugin_event)(info.evt)
			field = (*C.struct_ss_plugin_extract_field)(info.field)
			field.field_present = false
			extrReq = extrReqs.ExtractRequests().Get(int(field.field_id))
			extrReq.SetPtr(unsafe.Pointer(field))

			err := e.Extract(extrReq, sdk.NewEventReader(unsafe.Pointer(event)))
			if err != nil {
				e.(sdk.LastError).SetLastError(err)
				info.rc = C.int32_t(sdk.SSPluginFailure)
				continue
			}
		}
	}()
}

// StopAsync deinitializes and stops the asynchronous extraction mode, and
// must be called after StartAsync.
func StopAsync(e sdk.Extractor) {
	C.destroy_async_extractor()
	asyncWorkerRunning = false
}
