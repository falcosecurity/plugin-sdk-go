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
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go"
)

// PluginExtractStrFunc is used when using RegisterExtractors or
// RegisterAsyncExtractors.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractStrFunc func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string)

// PluginExtractU64Func is used when using RegisterExtractors or
// RegisterAsyncExtractors.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractU64Func func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64)

// These functions will be called by the sdk and are set in RegisterExtractors()/RegisterAsyncExtractors
var extractStrFunc PluginExtractStrFunc
var extractU64Func PluginExtractU64Func

func wrapExtractFuncs(plgState unsafe.Pointer, evt unsafe.Pointer, numFields uint32, fields unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func) int32 {

	event := (*C.struct_ss_plugin_event)(evt)
	dataBuf := C.GoBytes(unsafe.Pointer(event.data), C.int(event.datalen))

	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	flds := (*[1 << 28]C.struct_ss_plugin_extract_field)(unsafe.Pointer(fields))[:numFields:numFields]

	var i uint32
	for i = 0; i < numFields; i++ {
		fieldStr := C.GoString((*C.char)(flds[i].field))
		argStr := C.GoString((*C.char)(flds[i].arg))

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

			dataBuf := C.GoBytes(unsafe.Pointer(info.evt.data), C.int(info.evt.datalen))

			fieldStr := C.GoString((*C.char)(info.field.field))
			argStr := C.GoString((*C.char)(info.field.arg))

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

// NextFunc is the function type required by NextBatch().
type NextFunc func(plgState unsafe.Pointer, openState unsafe.Pointer) (*sdk.PluginEvent, int32)

// NextBatch is an helper function to be used within
// plugin_next_batch. It takes a Next() function as argument that
// returns a single sdk.PluginEvent struct pointer and calls that
// function as needed to populate a dynamically allocated array of
// ss_plugin_event structs with dynamically allocated data payloads.
//
// Example Usage:
//
//    func MyNext(plgState unsafe.Pointer, openState unsafe.Pointer) (*sdk.PluginEvent, int32) {
//        ret := &sdk.PluginEvent{}
//
//        // Populate ret here
//
//        return ret, sdk.SSPluginSuccess
//    }
//
//    //export plugin_next_batch
//    func plugin_next_batch(plgState unsafe.Pointer, openState unsafe.Pointer, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
//        evts, res := wrappers.NextBatch(plgState, openState, MyNext)
//        // .. convert sdk.PluginEvent to ss_plugin_event (see wrappers.Events())
//
//        return res
//    }
func NextBatch(plgState unsafe.Pointer, openState unsafe.Pointer, nextf NextFunc) ([]*sdk.PluginEvent, int32) {
	res := sdk.SSPluginSuccess

	evts := make([]*sdk.PluginEvent, 0)

	for len(evts) < sdk.MaxNextBatchEvents {
		var evt *sdk.PluginEvent
		evt, res = nextf(plgState, openState)
		if res == sdk.SSPluginSuccess {
			evts = append(evts, evt)
		} else {
			break
		}
	}

	// If the last result was Timeout/EOF, but there actually are
	// some events, return success instead. (This could happen if
	// nextf returned some events and then a Timeout/EOF).
	if (res == sdk.SSPluginTimeout || res == sdk.SSPluginEOF) && len(evts) > 0 {
		res = sdk.SSPluginSuccess
	}

	return evts, res
}

// Convert the provided slice of PluginEvents into a C array of
// ss_plugin_event structs, suitable for returning in
// plugin_next/plugin_next_batch.
//
// Example usage:
//    //export plugin_next_batch
//    func plugin_next_batch(plgState unsafe.Pointer, openState unsafe.Pointer, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
//        evts, res := wrappers.NextBatch(plgState, openState, MyNext)
//        if res == sdk.SSPluginSuccess {
//            *retEvts = (*C.ss_plugin_event)(wrappers.Events(evts))
//            *nevts = (uint32)(len(evts))
//        }
//    }
//
// The return value is an unsafe.Pointer, as the C.ss_plugin_event
// type is package-specific and can't be easily used outside the
// package (See https://github.com/golang/go/issues/13467)
func Events(evts []*sdk.PluginEvent) unsafe.Pointer {
	ret := (*C.ss_plugin_event)(C.malloc((C.ulong)(len(evts))*C.sizeof_ss_plugin_event))

	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	length := len(evts)
	cevts := (*[1 << 28]C.ss_plugin_event)(unsafe.Pointer(ret))[:length:length]
	for i := 0; i < length; i++ {
		cevts[i].data = (*C.uchar)(C.CBytes(evts[i].Data))
		cevts[i].datalen = (C.uint)(len(evts[i].Data))
		cevts[i].ts = (C.uint64_t)(evts[i].Timestamp)
	}

	return (unsafe.Pointer)(ret)
}
