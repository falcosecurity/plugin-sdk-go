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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct ss_plugin_event
{
	uint64_t evtnum;
	uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

typedef struct ss_plugin_extract_field
{
	const char *field;
	const char *arg;
	uint32_t ftype;

	bool field_present;
	char *res_str;
	uint64_t res_u64;
} ss_plugin_extract_field;

typedef bool (*cb_wait_t)(void* wait_ctx);

typedef struct async_extractor_info
{
	// Pointer as this allows swapping out events from other
	// structs.
	const ss_plugin_event *evt;
	ss_plugin_extract_field *field;
	int32_t rc;
	cb_wait_t cb_wait;
	void* wait_ctx;
} async_extractor_info;

bool wait_bridge(async_extractor_info *info)
{
	return info->cb_wait(info->wait_ctx);
};

void fill_event(ss_plugin_event *evts, int idx, uint8_t *data, uint32_t datalen, uint64_t ts)
{
   evts[idx].data = data;
   evts[idx].datalen = datalen;
   evts[idx].ts = ts;
}


*/
import "C"
import (
	"unsafe"

	"github.com/mstemm/plugin-sdk-go"
)

// PluginExtractStrFunc is used when setting up an async extractor via
// RegisterAsyncExtractors or when extacting fields using WrapExtractFuncs.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractStrFunc func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string)

// PluginExtractU64Func is used when setting up an async extractor via
// RegisterAsyncExtractors or when extacting fields using WrapExtractFuncs.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractU64Func func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64)

// WrapExtractFuncs allows a plugin to define higher-level go
// functions that work with go types to return field
// values. WrapExtractFuncs will call the provided functions to
// extract values based on the field type and take care of the
// conversion between go types and C types as well as iterating over an
// array of ss_plugin_extract_field structs.
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
//    //export plugin_extract_fields
//    func plugin_extract_fields(plgState unsafe.Pointer, evt *C.struct_ss_plugin_event, numFields uint32, fields *C.struct_ss_plugin_extract_field) int32 {
//       return wrappers.WrapExtractFuncs(plgState, unsafe.Pointer(evt), numFields, unsafe.Pointer(fields), MyExtractStrFunc, MyExtractu64Func)
//    }
func WrapExtractFuncs(plgState unsafe.Pointer, evt unsafe.Pointer, numFields uint32, fields unsafe.Pointer,
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
			if present {
				flds[i].field_present = C.bool(true)
				flds[i].res_str = C.CString(str)
			} else {
				flds[i].field_present = C.bool(false)
				flds[i].res_str = nil
			}
		case sdk.ParamTypeUint64:
			present, u64 := u64ExtractorFunc(plgState, uint64(event.evtnum), dataBuf, uint64(event.ts), fieldStr, argStr)
			if present {
				flds[i].field_present = C.bool(true)
				flds[i].res_u64 = C.uint64_t(u64)
			} else {
				flds[i].field_present = C.bool(false)
			}
		}
	}

	return sdk.ScapSuccess
}

// RegisterAsyncExtractors is a helper function to be used within plugin_register_async_extractor.
//
// Intended usage as in the following example:
//
//     // A function to extract a single string field from an event
//     func extract_str(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
//       ...
//     }
//
//     // A function to extract a single uint64 field from an event
//     func extract_u64(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
//       ...
//     }
//
//     //export plugin_register_async_extractor
//     func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
//       return sinsp.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, plugin_extract_str)
//     }
//
//
// This function handles the details of coordinating with the plugin
// framework to wait for requests from the framework, calling
// strExtractorFunc/u64ExtractorFunc functions as needed, and
// returning values back to the plugin framework.
//
// If your plugin will return a high rate of events (e.g. >1000 sec)
// and you plan on using async field extraction in your plugin, you
// should always use this function inside
// plugin_register_async_extractor.
func RegisterAsyncExtractors(
	pluginState unsafe.Pointer,
	asyncExtractorInfo unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func,
) int32 {
	go func() {
		info := (*C.async_extractor_info)(asyncExtractorInfo)
		for C.wait_bridge(info) {
			info.rc = C.int32_t(sdk.ScapSuccess)

			dataBuf := C.GoBytes(unsafe.Pointer(info.evt.data), C.int(info.evt.datalen))

			fieldStr := C.GoString((*C.char)(info.field.field))
			argStr := C.GoString((*C.char)(info.field.arg))

			switch uint32(info.field.ftype) {
			case sdk.ParamTypeCharBuf:
				if strExtractorFunc != nil {
					present, str := strExtractorFunc(pluginState, uint64(info.evt.evtnum), dataBuf, uint64(info.evt.ts), fieldStr, argStr)

					if present {
						info.field.field_present = C.bool(true)
						info.field.res_str = C.CString(str)
					} else {
						info.field.field_present = C.bool(false)
						info.field.res_str = nil
					}
				} else {
					info.rc = C.int32_t(sdk.ScapNotSupported)
				}
			case sdk.ParamTypeUint64:
				if u64ExtractorFunc != nil {
					present, u64 := u64ExtractorFunc(pluginState, uint64(info.evt.evtnum), dataBuf, uint64(info.evt.ts), fieldStr, argStr)

					if (!present){
						info.field.field_present = C.bool(true)
					} else {
						info.field.field_present = C.bool(false)
						info.field.res_u64 = C.uint64_t(u64)
					}
				} else {
					info.rc = C.int32_t(sdk.ScapNotSupported)
				}
			default:
				info.rc = C.int32_t(sdk.ScapNotSupported)
			}
		}
	}()
	return sdk.ScapSuccess
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
//        return ret, sdk.ScapSuccess
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
	res := sdk.ScapSuccess

	evts := make([]*sdk.PluginEvent, 0)

	for len(evts) < sdk.MaxNextBatchEvents {
		var evt *sdk.PluginEvent
		evt, res = nextf(plgState, openState)
		if res == sdk.ScapSuccess {
			evts = append(evts, evt)
		} else if res == sdk.ScapEOF {
			// Return success but stop
			res = sdk.ScapSuccess
			break
		} else {
			break
		}
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
//        if res == sdk.ScapSuccess {
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
	for i, evt := range evts {
		C.fill_event(ret,
			(C.int)(i),
			(*C.uchar)(C.CBytes(evt.Data)),
			(C.uint)(len(evt.Data)),
			(C.uint64_t)(evt.Timestamp))
	}

	return (unsafe.Pointer)(ret)
}
