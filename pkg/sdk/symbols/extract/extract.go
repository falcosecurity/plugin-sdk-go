// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

// This package exports the following C function:
// - ss_plugin_rc plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
//
// The exported plugin_extract_fields requires s to be a handle
// of cgo.Handle from this SDK. The value of the s handle must implement
// the sdk.Extractor and sdk.ExtractRequests interfaces.
//
// This function is part of the plugin_api interface as defined in plugin_api.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package extract

/*
#include <stdlib.h>
#include "extract.h"
*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_extract_fields_sync
func plugin_extract_fields_sync(plgState C.uintptr_t, evt *C.ss_plugin_event_input, numFields uint32, fields *C.ss_plugin_extract_field, offsets *C.ss_plugin_extract_value_offsets) int32 {
	pHandle := cgo.Handle(plgState)
	extract := pHandle.Value().(sdk.Extractor)
	extrReqs := pHandle.Value().(sdk.ExtractRequests)

	// https://go.dev/wiki/cgo#turning-c-arrays-into-go-slices
	flds := (*[1 << 28]C.struct_ss_plugin_extract_field)(unsafe.Pointer(fields))[:numFields:numFields]
	var i uint32
	var extrReq sdk.ExtractRequest

	if offsets != nil {
		extrReqs.ExtractRequests().MakeOffsetArrayPtrs(unsafe.Pointer(offsets), numFields)
	}

	for i = 0; i < numFields; i++ {
		flds[i].res_len = (C.uint64_t)(0)
		extrReq = extrReqs.ExtractRequests().Get(int(flds[i].field_id))
		extrReq.SetPtr(unsafe.Pointer(&flds[i]))

		if offsets == nil {
			extrReq.SetOffsetPtrs(nil, nil)
		} else {
			extrReq.SetOffsetPtrs(
				unsafe.Add(unsafe.Pointer(offsets.start), i*C.sizeof_uint32_t),
				unsafe.Add(unsafe.Pointer(offsets.length), i*C.sizeof_uint32_t),
			)
		}

		err := extract.Extract(extrReq, sdk.NewEventReader(unsafe.Pointer(evt)))
		if err != nil {
			pHandle.Value().(sdk.LastError).SetLastError(err)
			return sdk.SSPluginFailure
		}
	}

	return sdk.SSPluginSuccess
}
