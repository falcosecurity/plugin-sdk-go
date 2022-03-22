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
	"fmt"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

func allocSSPluginExtractField(fid, ftype uint32, fname, farg string, list bool) (*_Ctype_ss_plugin_extract_field, func()) {
	ret := &_Ctype_ss_plugin_extract_field{}
	ret.field_id = _Ctype_uint32_t(fid)
	ret.ftype = _Ctype_uint32_t(ftype)
	ret.flist = _Ctype__Bool(list)

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

func getStrResSSPluingExtractField(t *testing.T, p *_Ctype_ss_plugin_extract_field, index int) string {
	if p.res_len < (_Ctype_uint64_t)(index) {
		t.Errorf("trying to access extract field res at index %d, but res len is %d", index, (int)(p.res_len))
	}
	return ptr.GoString(unsafe.Pointer((*((**_Ctype_char)(unsafe.Pointer(uintptr(*(*_Ctype_uintptr_t)(unsafe.Pointer(&p.res))) + uintptr(index*_Ciconst_sizeof_field_result_t)))))))
}

func getU64ResSSPluingExtractField(t *testing.T, ptr *_Ctype_ss_plugin_extract_field, index int) uint64 {
	if ptr.res_len < (_Ctype_uint64_t)(index) {
		t.Errorf("trying to access extract field res at index %d, but res len is %d", index, (int)(ptr.res_len))
	}
	return (uint64)(*((*_Ctype_uint64_t)(unsafe.Pointer(uintptr(*(*_Ctype_uintptr_t)(unsafe.Pointer(&ptr.res))) + uintptr(index*_Ciconst_sizeof_field_result_t)))))
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
		cstruct, freeCStruct := allocSSPluginExtractField(5, FieldTypeUint64, "test.field", "arg", false)
		req.SetPtr(unsafe.Pointer(cstruct))
		if req.FieldType() != FieldTypeUint64 || req.FieldID() != 5 || req.Field() != "test.field" || req.Arg() != "arg" {
			println(req.FieldType(), ", ", req.FieldID(), ", ", req.Field(), ", ", req.Arg())
			t.Errorf("could not read fields from sdk.ExtractRequest")
		}
		freeCStruct()
	}
	pool.Free()
}

func TestExtractRequestSetValue(t *testing.T) {
	// init test data
	testStr := "test str"
	testU64 := uint64(99)
	testStrList := make([]string, 0)
	testU64List := make([]uint64, 0)
	for i := 0; i < minResultBufferLen+1; i++ { // cause a list resizing
		testStrList = append(testStrList, fmt.Sprintf("test-%d", i))
		testU64List = append(testU64List, uint64(i))
	}

	// init extract requests
	pool := NewExtractRequestPool()
	u64Ptr, freeU64Ptr := allocSSPluginExtractField(1, FieldTypeUint64, "test.u64", "", false)
	u64ListPtr, freeU64ListPtr := allocSSPluginExtractField(2, FieldTypeUint64, "test.u64", "", true)
	strPtr, freeStrPtr := allocSSPluginExtractField(3, FieldTypeCharBuf, "test.str", "", false)
	strListPtr, freeStrListPtr := allocSSPluginExtractField(4, FieldTypeCharBuf, "test.str", "", true)
	u64Req := pool.Get(0)
	u64ReqList := pool.Get(1)
	strReq := pool.Get(2)
	strReqList := pool.Get(3)
	u64Req.SetPtr(unsafe.Pointer(u64Ptr))
	u64ReqList.SetPtr(unsafe.Pointer(u64ListPtr))
	strReq.SetPtr(unsafe.Pointer(strPtr))
	strReqList.SetPtr(unsafe.Pointer(strListPtr))

	// check that info is passed-through correctly
	if u64Req.FieldID() != 1 {
		t.Errorf("expected value '%d', but found '%d'", 1, u64Req.FieldID())
	}
	if u64Req.FieldType() != FieldTypeUint64 {
		t.Errorf("expected value '%d', but found '%d'", FieldTypeUint64, u64Req.FieldType())
	}
	if u64Req.Field() != "test.u64" {
		t.Errorf("expected value '%s', but found '%s'", "test.u64", u64Req.Field())
	}
	if u64Req.Arg() != "" {
		t.Errorf("expected value '%s', but found '%s'", "", u64Req.Arg())
	}
	if u64Req.IsList() != false {
		t.Errorf("expected value '%t', but found '%t'", false, u64Req.IsList())
	}
	if strReqList.IsList() != true {
		t.Errorf("expected value '%t', but found '%t'", true, strReqList.IsList())
	}

	// check panics
	assertPanic(t, func() {
		u64Req.SetValue("test")
	})
	assertPanic(t, func() {
		strReq.SetValue(uint64(1))
	})

	// check set correct values
	u64Req.SetValue(testU64)
	if getU64ResSSPluingExtractField(t, u64Ptr, 0) != testU64 {
		t.Errorf("expected value '%d', but found '%d'", testU64, getU64ResSSPluingExtractField(t, u64Ptr, 0))
	}
	u64ReqList.SetValue(testU64List)
	for i, d := range testU64List {
		if getU64ResSSPluingExtractField(t, u64ListPtr, i) != d {
			t.Errorf("expected value '%d', but found '%d'", testU64, getU64ResSSPluingExtractField(t, u64Ptr, i))
		}
	}
	strReq.SetValue(testStr)
	if getStrResSSPluingExtractField(t, strPtr, 0) != testStr {
		t.Errorf("expected value '%s', but found '%s'", testStr, getStrResSSPluingExtractField(t, strPtr, 0))
	}
	strReqList.SetValue(testStrList)
	for i, s := range testStrList {
		if getStrResSSPluingExtractField(t, strListPtr, i) != s {
			t.Errorf("expected value '%s', but found '%s'", s, getStrResSSPluingExtractField(t, strPtr, i))
		}
	}

	pool.Free()
	freeU64Ptr()
	freeU64ListPtr()
	freeStrPtr()
	freeStrListPtr()
}
