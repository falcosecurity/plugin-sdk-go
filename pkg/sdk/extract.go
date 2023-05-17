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

package sdk

/*
#include "plugin_types.h"
#include <stdlib.h>
#include <string.h>

// NOTE: This is just an replica of the anonymous union nested inside
// ss_plugin_extract_field. The only difference is that each union field has
// one pointer level less than its equivalent of ss_plugin_extract_field.
// Keep this in sync with plugin_types.h in case new types will be supported.
typedef union {
	const char* str;
	uint64_t u64;
	uint32_t u32;
	ss_plugin_bool boolean;
	ss_plugin_byte_buffer buf;
} field_result_t;

*/
import "C"
import (
	"net"
	"reflect"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

const (
	// Initial and minimum length with which the array of results is allocated
	// for a each extractRequest struct.
	minResultBufferLen = 512
)

// ExtractRequest represents an high-level abstraction that wraps a pointer to
// a ss_plugin_extract_field C structure, providing methods for accessing its
// fields in a go-friendly way.
type ExtractRequest interface {
	// FieldID returns id of the field, as of its index in the list of fields
	// returned by plugin_get_fields
	FieldID() uint64
	//
	// FieldType returns the type of the field for which the value extraction
	// is requested. For now, the supported types are:
	//  - sdk.FieldTypeBool
	//  - sdk.FieldTypeUint64
	//  - sdk.FieldTypeCharBuf
	//  - sdk.FieldTypeRelTime
	//  - sdk.FieldTypeAbsTime
	//  - sdk.FieldTypeIPAddr
	//  - sdk.FieldTypeIPNet
	FieldType() uint32
	//
	// Field returns the name of the field for which the value extraction
	// is requested.
	Field() string
	//
	// ArgKey must be used when the field arg is a generic string (like a key
	// in a lookup operation). This field must have the `isKey` flag enabled.
	ArgKey() string
	//
	// ArgIndex must be used when the field arg is an index (0<=index<=2^64-1).
	// This field must have the `isIndex` flag enabled.
	ArgIndex() uint64
	//
	// ArgPresent clearly defines when an argument is valid or not.
	ArgPresent() bool
	//
	// IsList returns true if the field extracts lists of values.
	IsList() bool
	//
	// SetValue sets the extracted value for the requested field.
	//
	// The underlying type of v must be compatible with the field type
	// associated to this extract request (as the returned by FieldType()),
	// otherwise SetValue will panic.
	//
	// Coherently to the FieldType of the extraction request, this function
	// panics if the passed value is not one of the following types (or slices
	// of them, in case IsList() returns true):
	//  - sdk.FieldTypeBool: bool
	//  - sdk.FieldTypeUint64: uint64
	//  - sdk.FieldTypeCharBuf: string
	//  - sdk.FieldTypeRelTime: time.Duration, *time.Duration
	//  - sdk.FieldTypeAbsTime: time.Time, *time.Time
	//  - sdk.FieldTypeIPAddr: net.IP, *net.IP
	//  - sdk.FieldTypeIPNet: net.IPNet, *net.IPNet
	SetValue(v interface{})
	//
	// SetPtr sets a pointer to a ss_plugin_extract_field C structure to
	// be wrapped in this instance of ExtractRequest.
	SetPtr(unsafe.Pointer)
}

// ExtractRequestPool represents a pool of reusable ExtractRequest objects.
// Each ExtractRequest can be reused by calling its SetPtr method to wrap
// a new ss_plugin_extract_field C structure pointer.
type ExtractRequestPool interface {
	// Get returns an instance of ExtractRequest at the requestIndex
	// position inside the pool. Indexes can be non-contiguous.
	Get(requestIndex int) ExtractRequest
	//
	// Free deallocates any memory used by the pool that can't be disposed
	// through garbage collection. The behavior of Free after the first call
	// is undefined.
	Free()
}

type extractRequestPool struct {
	reqs map[uint]*extractRequest
}

func (e *extractRequestPool) Get(requestIndex int) ExtractRequest {
	r, ok := e.reqs[uint(requestIndex)]
	if !ok && requestIndex >= 0 {
		r = &extractRequest{
			resBuf:     (*C.field_result_t)(C.malloc((C.size_t)(minResultBufferLen * C.sizeof_field_result_t))),
			resBufLen:  minResultBufferLen,
			resStrBufs: []StringBuffer{&ptr.StringBuffer{}},
			resValPtrs: make([]unsafe.Pointer, minResultBufferLen),
		}
		for i := 0; i < minResultBufferLen; i++ {
			ptr := (*C.field_result_t)(unsafe.Pointer(uintptr(unsafe.Pointer(r.resBuf)) + uintptr(i*C.sizeof_field_result_t)))
			r.resValPtrs[i] = unsafe.Pointer(ptr)
		}
		e.reqs[uint(requestIndex)] = r
	}
	return r
}

func (e *extractRequestPool) Free() {
	for _, v := range e.reqs {
		for _, b := range v.resStrBufs {
			b.Free()
		}
		C.free(unsafe.Pointer(v.resBuf))
	}
}

// NewExtractRequestPool returns a new empty ExtractRequestPool.
func NewExtractRequestPool() ExtractRequestPool {
	pool := &extractRequestPool{
		reqs: make(map[uint]*extractRequest),
	}
	return pool
}

type extractRequest struct {
	req *C.ss_plugin_extract_field
	// Pointer to a C-allocated array of field_result_t
	resBuf *C.field_result_t
	// Length of the array pointed by resBuf
	resBufLen uint32
	// List of StringBuffer to return string results
	resStrBufs []StringBuffer
	// List of BytesReadWriter to return binary results
	resBinBufs []ptr.BytesReadWriter
	// List of *field_result_t to be filled with the values of a request
	resValPtrs []unsafe.Pointer
}

func (e *extractRequest) SetPtr(pef unsafe.Pointer) {
	e.req = (*C.ss_plugin_extract_field)(pef)
}

func (e *extractRequest) FieldID() uint64 {
	return uint64(e.req.field_id)
}

func (e *extractRequest) FieldType() uint32 {
	return uint32(e.req.ftype)
}

func (e *extractRequest) Field() string {
	return ptr.GoString(unsafe.Pointer(e.req.field))
}

func (e *extractRequest) ArgKey() string {
	return ptr.GoString(unsafe.Pointer(e.req.arg_key))
}

func (e *extractRequest) ArgIndex() uint64 {
	return uint64(e.req.arg_index)
}

func (e *extractRequest) ArgPresent() bool {
	return e.req.arg_present != 0
}

func (e *extractRequest) IsList() bool {
	return e.req.flist != 0
}

func (e *extractRequest) boolToU32(v bool) uint32 {
	if v {
		return uint32(1)
	}
	return uint32(0)
}

func (e *extractRequest) resizeResValPtrs(length int) []unsafe.Pointer {
	if e.resBufLen < uint32(length) {
		C.free(unsafe.Pointer(e.resBuf))
		e.resBufLen = uint32(length)
		e.resBuf = (*C.field_result_t)(C.malloc((C.size_t)(e.resBufLen * C.sizeof_field_result_t)))
		e.resValPtrs = make([]unsafe.Pointer, length)
		for i := 0; i < length; i++ {
			ptr := (*C.field_result_t)(unsafe.Pointer(uintptr(unsafe.Pointer(e.resBuf)) + uintptr(i*C.sizeof_field_result_t)))
			e.resValPtrs[i] = unsafe.Pointer(ptr)
		}
	}
	e.req.res_len = (C.uint64_t)(length)
	return e.resValPtrs[:length]
}

func (e *extractRequest) SetValue(v interface{}) {
	switch e.FieldType() {
	case FieldTypeBool:
		if e.IsList() {
			for i, ptr := range e.resizeResValPtrs(len(v.([]bool))) {
				*((*C.uint64_t)(ptr)) = (C.uint64_t)(e.boolToU32((v.([]bool))[i]))
			}
		} else {
			ptr := e.resizeResValPtrs(1)[0]
			*((*C.uint64_t)(ptr)) = (C.uint64_t)(e.boolToU32(v.(bool)))
		}
	case FieldTypeUint64:
		if e.IsList() {
			for i, ptr := range e.resizeResValPtrs(len(v.([]uint64))) {
				*((*C.uint64_t)(ptr)) = (C.uint64_t)((v.([]uint64))[i])
			}
		} else {
			ptr := e.resizeResValPtrs(1)[0]
			*((*C.uint64_t)(ptr)) = (C.uint64_t)(v.(uint64))
		}
	case FieldTypeCharBuf:
		if e.IsList() {
			for i, out := range e.resizeResValPtrs(len(v.([]string))) {
				if len(e.resStrBufs) <= i {
					e.resStrBufs = append(e.resStrBufs, &ptr.StringBuffer{})
				}
				e.resStrBufs[i].Write(v.([]string)[i])
				*((**C.char)(out)) = (*C.char)(e.resStrBufs[i].CharPtr())
			}
		} else {
			out := e.resizeResValPtrs(1)[0]
			e.resStrBufs[0].Write(v.(string))
			*((**C.char)(out)) = (*C.char)(e.resStrBufs[0].CharPtr())
		}
	case FieldTypeRelTime:
		if e.IsList() {
			if val, ok := v.([]time.Duration); ok {
				for i, ptr := range e.resizeResValPtrs(len(val)) {
					*((*C.uint64_t)(ptr)) = (C.uint64_t)(val[i].Nanoseconds())
				}
			} else {
				for i, ptr := range e.resizeResValPtrs(len(v.([]*time.Duration))) {
					*((*C.uint64_t)(ptr)) = (C.uint64_t)(v.([]*time.Duration)[i].Nanoseconds())
				}
			}
		} else {
			ptr := e.resizeResValPtrs(1)[0]
			if val, ok := v.(time.Duration); ok {
				*((*C.uint64_t)(ptr)) = (C.uint64_t)(val.Nanoseconds())
			} else {
				*((*C.uint64_t)(ptr)) = (C.uint64_t)(v.(*time.Duration).Nanoseconds())
			}
		}
	case FieldTypeAbsTime:
		if e.IsList() {
			if val, ok := v.([]time.Time); ok {
				for i, ptr := range e.resizeResValPtrs(len(val)) {
					*((*C.uint64_t)(ptr)) = (C.uint64_t)(val[i].UnixNano())
				}
			} else {
				for i, ptr := range e.resizeResValPtrs(len(v.([]*time.Time))) {
					*((*C.uint64_t)(ptr)) = (C.uint64_t)(v.([]*time.Time)[i].UnixNano())
				}
			}
		} else {
			ptr := e.resizeResValPtrs(1)[0]
			if val, ok := v.(time.Time); ok {
				*((*C.uint64_t)(ptr)) = (C.uint64_t)(val.UnixNano())
			} else {
				*((*C.uint64_t)(ptr)) = (C.uint64_t)(v.(*time.Time).UnixNano())
			}
		}
	case FieldTypeIPAddr:
		if e.IsList() {
			if val, ok := v.([]net.IP); ok {
				for i, ptr := range e.resizeResValPtrs(len(val)) {
					val := ([]byte)((val)[i])
					(*C.struct_ss_plugin_byte_buffer)(ptr).len = C.uint32_t(len(val))
					(*C.struct_ss_plugin_byte_buffer)(ptr).ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&val)).Data)
				}
			} else {
				for i, ptr := range e.resizeResValPtrs(len(v.([]*net.IP))) {
					val := ([]byte)(*(v.([]*net.IP))[i])
					(*C.struct_ss_plugin_byte_buffer)(ptr).len = C.uint32_t(len(val))
					(*C.struct_ss_plugin_byte_buffer)(ptr).ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&val)).Data)
				}
			}
		} else {
			var val []byte
			ptr := e.resizeResValPtrs(1)[0]
			if ipv, ok := v.(net.IP); ok {
				val = ([]byte)(ipv)
			} else {
				val = ([]byte)(*(v.(*net.IP)))
			}
			(*C.struct_ss_plugin_byte_buffer)(ptr).len = C.uint32_t(len(val))
			(*C.struct_ss_plugin_byte_buffer)(ptr).ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&val)).Data)
		}
	case FieldTypeIPNet:
		if e.IsList() {
			if ipv, ok := v.([]net.IPNet); ok {
				for i, ptr := range e.resizeResValPtrs(len(ipv)) {
					val := ([]byte)((ipv)[i].IP)
					(*C.struct_ss_plugin_byte_buffer)(ptr).len = C.uint32_t(len(val))
					(*C.struct_ss_plugin_byte_buffer)(ptr).ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&val)).Data)
				}
			} else {
				for i, ptr := range e.resizeResValPtrs(len(v.([]*net.IPNet))) {
					val := ([]byte)(*(v.([]*net.IP))[i])
					(*C.struct_ss_plugin_byte_buffer)(ptr).len = C.uint32_t(len(val))
					(*C.struct_ss_plugin_byte_buffer)(ptr).ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&val)).Data)
				}
			}
		} else {
			var val []byte
			ptr := e.resizeResValPtrs(1)[0]
			if ipv, ok := v.(net.IPNet); ok {
				val = ([]byte)(ipv.IP)
			} else {
				val = ([]byte)(v.(*net.IPNet).IP)
			}
			(*C.struct_ss_plugin_byte_buffer)(ptr).len = C.uint32_t(len(val))
			(*C.struct_ss_plugin_byte_buffer)(ptr).ptr = unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&val)).Data)
		}
	default:
		panic("plugin-sdk-go/sdk: called SetValue with unsupported field type")
	}
	*((*C.uintptr_t)(unsafe.Pointer(&e.req.res))) = *(*C.uintptr_t)(unsafe.Pointer(&e.resBuf))
}
