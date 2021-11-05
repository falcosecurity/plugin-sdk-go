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

import (
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

func allocSSPluginExtractField(fid, ftype uint32, fname, farg string) (*_Ctype_ss_plugin_extract_field, func()) {
	ret := &_Ctype_ss_plugin_extract_field{}
	ret.field_id = _Ctype_uint(fid)
	ret.ftype = _Ctype_uint(ftype)

	argBuf := ptr.StringBuffer{}
	fnameBuf := ptr.StringBuffer{}
	fnameBuf.Write(fname)
	ret.field = (*_Ctype_char)(fnameBuf.CharPtr())
	if len(farg) > 0 {
		argBuf.Write(farg)
		ret.arg = (*_Ctype_char)(argBuf.CharPtr())
	} else {
		ret.arg = nil
	}

	return ret, func() {
		argBuf.Free()
		fnameBuf.Free()
	}
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}

func TestNewExtractRequestPool(t *testing.T) {
	pool := NewExtractRequestPool()
	// Access should be non-contiguous
	for i := 0; i < 20; i += 2 {
		req := pool.Get(i)
		cstruct, freeCStruct := allocSSPluginExtractField(5, ParamTypeUint64, "test.field", "arg")
		req.SetPtr(unsafe.Pointer(cstruct))
		if req.FieldType() != ParamTypeUint64 || req.FieldID() != 5 || req.Field() != "test.field" || req.Arg() != "arg" {
			println(req.FieldType(), ", ", req.FieldID(), ", ", req.Field(), ", ", req.Arg())
			t.Errorf("could not read fields from sdk.ExtractRequest")
		}
		freeCStruct()
	}
	pool.Free()
}

func TestExtractRequestSetValue(t *testing.T) {
	pool := NewExtractRequestPool()
	u64Ptr, freeU64Ptr := allocSSPluginExtractField(1, ParamTypeUint64, "test.u64", "")
	strPtr, freeStrPtr := allocSSPluginExtractField(2, ParamTypeCharBuf, "test.str", "")
	u64Req := pool.Get(0)
	strReq := pool.Get(1)
	u64Req.SetPtr(unsafe.Pointer(u64Ptr))
	strReq.SetPtr(unsafe.Pointer(strPtr))

	assertPanic(t, func() {
		u64Req.SetValue("test")
	})
	assertPanic(t, func() {
		strReq.SetValue(uint64(1))
	})
	u64Req.SetValue(uint64(1))
	strReq.SetValue("test")

	pool.Free()
	freeU64Ptr()
	freeStrPtr()
}
