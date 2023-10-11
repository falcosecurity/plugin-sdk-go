// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
	"net"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

func boolToUint32(v bool) _Ctype_uint32_t {
	if v {
		return _Ctype_uint32_t(1)
	}
	return _Ctype_uint32_t(0)
}

func allocSSPluginExtractField(fid, ftype uint32, fname, farg_key string, farg_index uint64, farg_present bool, list bool) (*_Ctype_ss_plugin_extract_field, func()) {
	ret := &_Ctype_ss_plugin_extract_field{}
	ret.field_id = _Ctype_uint32_t(fid)
	ret.ftype = _Ctype_uint32_t(ftype)
	ret.arg_present = boolToUint32(farg_present)
	ret.flist = boolToUint32(list)
	ret.arg_index = _Ctype_uint64_t(farg_index)

	argKeyBuf := ptr.StringBuffer{}
	fnameBuf := ptr.StringBuffer{}
	fnameBuf.Write(fname)
	ret.field = (*_Ctype_char)(fnameBuf.CharPtr())
	if len(farg_key) > 0 {
		argKeyBuf.Write(farg_key)
		ret.arg_key = (*_Ctype_char)(argKeyBuf.CharPtr())
	} else {
		ret.arg_key = nil
	}

	return ret, func() {
		argKeyBuf.Free()
		fnameBuf.Free()
	}
}

func getBoolResSSPluingExtractField(t *testing.T, ptr *_Ctype_ss_plugin_extract_field, index int) bool {
	if ptr.res_len < (_Ctype_uint64_t)(index) {
		t.Errorf("trying to access extract field res at index %d, but res len is %d", index, (int)(ptr.res_len))
	}
	value := (uint32)(*((*_Ctype_uint32_t)(unsafe.Pointer(uintptr(*(*_Ctype_uintptr_t)(unsafe.Pointer(&ptr.res))) + uintptr(index*_Ciconst_sizeof_uint32_t)))))
	return value != uint32(0)
}

func getStrResSSPluingExtractField(t *testing.T, p *_Ctype_ss_plugin_extract_field, index int) string {
	if p.res_len < (_Ctype_uint64_t)(index) {
		t.Errorf("trying to access extract field res at index %d, but res len is %d", index, (int)(p.res_len))
	}
	return ptr.GoString(unsafe.Pointer((*((**_Ctype_char)(unsafe.Pointer(uintptr(*(*_Ctype_uintptr_t)(unsafe.Pointer(&p.res))) + uintptr(index*_Ciconst_sizeof_uintptr_t)))))))
}

func getU64ResSSPluingExtractField(t *testing.T, ptr *_Ctype_ss_plugin_extract_field, index int) uint64 {
	if ptr.res_len < (_Ctype_uint64_t)(index) {
		t.Errorf("trying to access extract field res at index %d, but res len is %d", index, (int)(ptr.res_len))
	}
	return (uint64)(*((*_Ctype_uint64_t)(unsafe.Pointer(uintptr(*(*_Ctype_uintptr_t)(unsafe.Pointer(&ptr.res))) + uintptr(index*_Ciconst_sizeof_uint64_t)))))
}

func getBinResSSPluingExtractField(t *testing.T, p *_Ctype_ss_plugin_extract_field, index int) []byte {
	if p.res_len < (_Ctype_uint64_t)(index) {
		t.Errorf("trying to access extract field res at index %d, but res len is %d", index, (int)(p.res_len))
	}

	bufListPtr := *(*unsafe.Pointer)(unsafe.Pointer(&p.res))
	curBufPtr := (unsafe.Pointer)(unsafe.Pointer(uintptr(bufListPtr) + uintptr(index*_Ciconst_sizeof_field_result_t)))
	size := *(*uint32)(curBufPtr)
	buf := make([]byte, size)
	ptrBytes := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(curBufPtr) + uintptr(8)))
	for i := 0; i < int(size); i++ {
		buf[i] = *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(ptrBytes)) + uintptr(i)))
	}
	return buf
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
		cstruct, freeCStruct := allocSSPluginExtractField(5, FieldTypeUint64, "test.field", "5", 5, true, false)
		req.SetPtr(unsafe.Pointer(cstruct))
		if req.FieldType() != FieldTypeUint64 || req.FieldID() != 5 || req.Field() != "test.field" || req.ArgKey() != "5" ||
			req.ArgIndex() != 5 || req.ArgPresent() != true || req.IsList() != false {
			println(req.FieldType(), ", ", req.FieldID(), ", ", req.Field(), ", ", req.ArgKey(), ", ", req.ArgIndex())
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
	testBool := true
	testIPv6 := net.IPv6loopback
	testStrList := make([]string, 0)
	testU64List := make([]uint64, 0)
	testBoolList := make([]bool, 0)
	dataArray := make([]byte, (minResultBufferLen+1)*int(len(testIPv6)))
	for i := 0; i < (minResultBufferLen+1)*int(len(testIPv6)); i++ {
		dataArray[i] = byte(i)
	}
	testIPv6List := make([]net.IP, minResultBufferLen+1)
	for i := 0; i < minResultBufferLen+1; i++ {
		testStrList = append(testStrList, fmt.Sprintf("test-%d", i))
		testU64List = append(testU64List, uint64(i))
		testBoolList = append(testBoolList, i%3 == 0)
		testIPv6List[i] = dataArray[i*len(testIPv6) : (i+1)*len(testIPv6)]
	}

	// init extract requests
	pool := NewExtractRequestPool()
	u64Ptr, freeU64Ptr := allocSSPluginExtractField(1, FieldTypeUint64, "test.u64", "", 0, true, false)
	u64ListPtr, freeU64ListPtr := allocSSPluginExtractField(2, FieldTypeUint64, "test.u64", "", 0, true, true)
	strPtr, freeStrPtr := allocSSPluginExtractField(3, FieldTypeCharBuf, "test.str", "", 0, true, false)
	strListPtr, freeStrListPtr := allocSSPluginExtractField(4, FieldTypeCharBuf, "test.str", "", 0, true, true)
	boolPtr, freeBoolPtr := allocSSPluginExtractField(5, FieldTypeBool, "test.bool", "", 0, true, false)
	boolListPtr, freeBoolListPtr := allocSSPluginExtractField(6, FieldTypeBool, "test.bool", "", 0, true, true)
	binPtr, freeBinPtr := allocSSPluginExtractField(7, FieldTypeIPAddr, "test.ipv6addr", "", 0, true, false)
	binListPtr, freeBinListPtr := allocSSPluginExtractField(8, FieldTypeIPAddr, "test.ipv6addr", "", 0, true, true)
	u64Req := pool.Get(0)
	u64ReqList := pool.Get(1)
	strReq := pool.Get(2)
	strReqList := pool.Get(3)
	boolReq := pool.Get(4)
	boolReqList := pool.Get(5)
	binReq := pool.Get(6)
	binReqList := pool.Get(7)
	u64Req.SetPtr(unsafe.Pointer(u64Ptr))
	u64ReqList.SetPtr(unsafe.Pointer(u64ListPtr))
	strReq.SetPtr(unsafe.Pointer(strPtr))
	strReqList.SetPtr(unsafe.Pointer(strListPtr))
	boolReq.SetPtr(unsafe.Pointer(boolPtr))
	boolReqList.SetPtr(unsafe.Pointer(boolListPtr))
	binReq.SetPtr(unsafe.Pointer(binPtr))
	binReqList.SetPtr(unsafe.Pointer(binListPtr))

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
	if u64Req.ArgKey() != "" {
		t.Errorf("expected value '%s', but found '%s'", "", u64Req.ArgKey())
	}
	if u64Req.ArgIndex() != 0 {
		t.Errorf("expected value '%s', but found '%s'", "", u64Req.ArgKey())
	}
	if u64Req.ArgPresent() != true {
		t.Errorf("expected value '%s', but found '%s'", "", u64Req.ArgKey())
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
		u64Req.SetValue(bool(true))
		boolReq.SetValue([]byte{0x41, 0x41, 0x41, 0x41})
	})
	assertPanic(t, func() {
		strReq.SetValue(uint64(1))
		strReq.SetValue(bool(true))
		boolReq.SetValue([]byte{0x41, 0x41, 0x41, 0x41})
	})
	assertPanic(t, func() {
		boolReq.SetValue(uint64(1))
		boolReq.SetValue("test")
		boolReq.SetValue([]byte{0x41, 0x41, 0x41, 0x41})
	})
	assertPanic(t, func() {
		binReq.SetValue(uint64(1))
		binReq.SetValue("test")
		binReq.SetValue(bool(true))
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
	boolReq.SetValue(testBool)
	if getBoolResSSPluingExtractField(t, boolPtr, 0) != testBool {
		t.Errorf("expected value '%v', but found '%v'", testBool, getBoolResSSPluingExtractField(t, boolPtr, 0))
	}
	boolReqList.SetValue(testBoolList)
	for i, b := range testBoolList {
		if getBoolResSSPluingExtractField(t, boolListPtr, i) != b {
			t.Errorf("expected value '%v', but found '%v' at index %d", b, getBoolResSSPluingExtractField(t, boolPtr, i), i)
		}
	}
	binReq.SetValue(testIPv6)
	testIPv6res := getBinResSSPluingExtractField(t, binPtr, 0)
	if len(testIPv6res) != len(testIPv6) {
		t.Errorf("expected value '%v', but found '%v'", testIPv6, getBinResSSPluingExtractField(t, binPtr, 0))
	} else {
		for i := 0; i < len(testIPv6); i++ {
			if testIPv6[i] != testIPv6res[i] {
				t.Errorf("expected value '%v', but found '%v'", testIPv6, getBinResSSPluingExtractField(t, binPtr, 0))
			}
		}
	}
	binReqList.SetValue(testIPv6List)
	for i, s := range testIPv6List {
		testIPv6res := getBinResSSPluingExtractField(t, binListPtr, i)
		if len(testIPv6res) != len(s) {
			t.Errorf("expected size '%v', but found '%v'", len(s), len(testIPv6res))
		} else {
			for k := 0; k < len(s); k++ {
				if s[k] != testIPv6res[k] {
					t.Errorf("expected value '%v', but found '%v'", s, testIPv6res)
				}
			}
		}

	}

	pool.Free()
	freeU64Ptr()
	freeU64ListPtr()
	freeStrPtr()
	freeStrListPtr()
	freeBoolPtr()
	freeBoolListPtr()
	freeBinPtr()
	freeBinListPtr()
}
