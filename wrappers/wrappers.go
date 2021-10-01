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

package wrappers

/*
#include "wrappers.h"
*/
import "C"
import (
	"io"
	"unsafe"

	sdk "github.com/falcosecurity/plugin-sdk-go"
)

// PluginExtractStrFunc is used when using RegisterExtractors or
// RegisterAsyncExtractors.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractStrFunc func(pluginState unsafe.Pointer, evtnum uint64, data io.ReadSeeker, ts uint64, field string, arg string) (bool, string)

// PluginExtractU64Func is used when using RegisterExtractors or
// RegisterAsyncExtractors.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractU64Func func(pluginState unsafe.Pointer, evtnum uint64, data io.ReadSeeker, ts uint64, field string, arg string) (bool, uint64)

// These functions will be called by the sdk and are set in RegisterExtractors()/RegisterAsyncExtractors
var extractStrFunc PluginExtractStrFunc
var extractU64Func PluginExtractU64Func

func wrapExtractFuncs(plgState unsafe.Pointer, evt unsafe.Pointer, numFields uint32, fields unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func) int32 {

	event := (*C.struct_ss_plugin_event)(evt)

	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	flds := (*[1 << 28]C.struct_ss_plugin_extract_field)(unsafe.Pointer(fields))[:numFields:numFields]
	dataBuf, err := sdk.NewBytesReadWriter(unsafe.Pointer(event.data), int64(event.datalen))
	if err != nil {
		// todo(jasondellaluce,leogr): error is lost here, what to do?
		return sdk.SSPluginFailure
	}

	var i uint32
	for i = 0; i < numFields; i++ {
		fieldStr := sdk.GoString(unsafe.Pointer(flds[i].field))
		argStr := sdk.GoString(unsafe.Pointer(flds[i].arg))

		switch uint32(flds[i].ftype) {
		case sdk.ParamTypeCharBuf:
			present, str := strExtractorFunc(plgState, uint64(event.evtnum), dataBuf, uint64(event.ts), fieldStr, argStr)
			flds[i].field_present = C.bool(present)
			if present {
				flds[i].res_str = C.CString(str)
			} else {
				flds[i].res_str = nil
			}
		case sdk.ParamTypeUint64:
			present, u64 := u64ExtractorFunc(plgState, uint64(event.evtnum), dataBuf, uint64(event.ts), fieldStr, argStr)
			flds[i].field_present = C.bool(present)
			if present {
				flds[i].res_u64 = C.uint64_t(u64)
			}
		}
	}

	return sdk.SSPluginSuccess
}

// RegisterExtractors (and its analog RegisterAsyncExtractors) allows a plugin
// to define higher-level go functions that work with go types to
// return field values.
//
// A plugin should call *either* RegisterExtractors or
// RegisterAsyncExtractors, exactly once, in the implementation of
// plugin_init(). The difference is that calling RegisterExtractors
// implements synchronous field extraction--a framework call to
// plugin_extract_fields() is handled directly by the plugin, via the
// wrapper.
//
// RegisterAsyncExtractors uses a more advanced, resource intensive
// approach to amortize the overhead of Cgo function calls across
// multiple calls to `extract_fields()`. Only use
// RegisterAsyncExtractors when a plugin is expected to generate a
// high volume of events (e.g. > 1000/second).
//
// Both RegisterExtractors/RegisterAsyncExtractors will call the provided
// functions to extract values based on the field type and take care
// of the conversion between go types and C types as well as iterating
// over an array of ss_plugin_extract_field structs.
//
// Here's an example:
//    func MyExtractStrFunc(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
//        switch field {
//        case "plugin.field1":
//            return true, "some-value-for-field-from-event"
//        default:
//             return false, ""
//        }
//
//        return false, ""
//    }
//
//    func MyExtractU64Func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
//        switch field {
//        case "plugin.field1":
//            var someValueForFieldFromEvent uint64 = 282;
//            return true, someValueForFieldFromEvent
//        default:
//        return false, 0
//        }
//
//        return false, 0
//    }
//
//    // Inside of plugin_init()
//    func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
//       ...
//       wrappers.RegisterExtractors(extract_str, extract_u64)
//    }
func RegisterExtractors(strExtractorFunc PluginExtractStrFunc, u64ExtractorFunc PluginExtractU64Func) {
	extractStrFunc = strExtractorFunc
	extractU64Func = u64ExtractorFunc
}

// RegisterAsyncExtractors (and its analog RegisterExtractors) allows a plugin
// to define higher-level go functions that work with go types to
// return field values.
//
// See the documentation for RegisterExtractors for more
// information. In most cases, this function is not required and a
// plugin should use RegisterExtractors instead.
//
// Here's an example:
//    func MyExtractStrFunc(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
//        ...
//    }
//
//    func MyExtractU64Func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
//        ...
//    }
//
//    // Inside of plugin_init()
//    func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
//       ...
//       // Spawns a spinlock goroutine to coordinate with the plugin framework.
//       wrappers.RegisterAsyncExtractors(plgState, extract_str, extract_u64)
//    }
func RegisterAsyncExtractors(
	pluginState unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func,
) {
	info := C.create_async_extractor()
	go func() {
		for C.async_extractor_wait(info) {
			info.rc = C.int32_t(sdk.SSPluginSuccess)

			fieldStr := sdk.GoString(unsafe.Pointer(info.field.field))
			argStr := sdk.GoString(unsafe.Pointer(info.field.arg))
			dataBuf, err := sdk.NewBytesReadWriter(unsafe.Pointer(info.evt.data), int64(info.evt.datalen))
			if err != nil {
				// todo(jasondellaluce,leogr): error is lost here, what to do?
				info.rc = C.int32_t(sdk.SSPluginFailure)
				continue
			}

			switch uint32(info.field.ftype) {
			case sdk.ParamTypeCharBuf:
				if strExtractorFunc != nil {
					present, str := strExtractorFunc(pluginState, uint64(info.evt.evtnum), dataBuf, uint64(info.evt.ts), fieldStr, argStr)

					info.field.field_present = C.bool(present)
					if present {
						info.field.res_str = C.CString(str)
					} else {
						info.field.res_str = nil
					}
				} else {
					info.rc = C.int32_t(sdk.SSPluginNotSupported)
				}
			case sdk.ParamTypeUint64:
				if u64ExtractorFunc != nil {
					present, u64 := u64ExtractorFunc(pluginState, uint64(info.evt.evtnum), dataBuf, uint64(info.evt.ts), fieldStr, argStr)

					info.field.field_present = C.bool(present)
					if present {
						info.field.res_u64 = C.uint64_t(u64)
					}
				} else {
					info.rc = C.int32_t(sdk.SSPluginNotSupported)
				}
			default:
				info.rc = C.int32_t(sdk.SSPluginNotSupported)
			}
		}
	}()
}

// UnregisterAsyncExtractors() stops the goroutine started in
// RegisterAsyncExtractors(). If a plugin called
// RegisterAsyncExtractors() in plugin_init, it should call
// UnregisterAsyncExtractors during plugin_destory.
func UnregisterAsyncExtractors() {
	C.destroy_async_extractor()
}

//export plugin_extract_fields_sync
func plugin_extract_fields_sync(plgState unsafe.Pointer, evt *C.ss_plugin_event, numFields uint32, fields *C.ss_plugin_extract_field) int32 {

	if extractStrFunc == nil || extractU64Func == nil {
		return sdk.SSPluginFailure
	}

	return wrapExtractFuncs(plgState, unsafe.Pointer(evt), numFields, unsafe.Pointer(fields), extractStrFunc, extractU64Func)
}
