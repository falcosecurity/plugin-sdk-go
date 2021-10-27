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
#include "plugin_info.h"
*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

type ExtractRequest interface {
	FieldID() uint64
	Field() string
	Arg() string
	SetStrValue(v string)
	SetU64Value(v uint64)
	SetPtr(unsafe.Pointer) // ?
}

type ExtractRequestPool interface {
	Get(requestIndex int) ExtractRequest
	Free()
}

type extractRequestPool struct {
	reqs map[uint]*extractRequest
}

func (e *extractRequestPool) Get(requestIndex int) ExtractRequest {
	r, ok := e.reqs[uint(requestIndex)]
	if !ok && requestIndex >= 0 {
		r = &extractRequest{
			strBuf: &ptr.StringBuffer{},
		}
		e.reqs[uint(requestIndex)] = r
	}
	return r
}

func (e *extractRequestPool) Free() {
	for _, v := range e.reqs {
		v.strBuf.Free()
	}
}

func NewExtractRequestPool() ExtractRequestPool {
	pool := &extractRequestPool{
		reqs: make(map[uint]*extractRequest),
	}
	return pool
}

type extractRequest struct {
	req    *C.ss_plugin_extract_field
	strBuf StringBuffer
}

func (e *extractRequest) SetPtr(pef unsafe.Pointer) {
	e.req = (*C.ss_plugin_extract_field)(pef)
}

func (e *extractRequest) FieldID() uint64 {
	return uint64(e.req.field_id)
}

func (e *extractRequest) Field() string {
	return ptr.GoString(unsafe.Pointer(e.req.field))
}

func (e *extractRequest) Arg() string {
	return ptr.GoString(unsafe.Pointer(e.req.arg))
}

func (e *extractRequest) SetStrValue(v string) {
	e.strBuf.Write(v)
	e.req.res_str = (*C.char)(e.strBuf.CharPtr())
	e.req.field_present = true
}

func (e *extractRequest) SetU64Value(v uint64) {
	e.req.res_u64 = (C.ulong)(v)
	e.req.field_present = true
}
