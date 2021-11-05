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

package ptr

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"
)

const (
	testString = "hello poiana"
)

func TestGoStringPointer(t *testing.T) {
	// Allocate a buffer and encode a C-like string into it
	bytes := bytes.NewBufferString(testString + " ").Bytes()
	bytes[len(bytes)-1] = cStringNullTerminator

	// Use the sdk GoString to create a Go-friently string
	// view of the buffer above
	bytesPtr := unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Data)
	str := GoString(bytesPtr)
	if len(str) != len(testString) || str != testString {
		t.Errorf("str=%s, len=%d", str, len(str))
	}

	// Editing buffer should make the string change too,
	// because they point to the same memory location
	editPos := 0
	editByte := byte('X')
	bytes[editPos] = editByte
	if len(str) != len(testString) || str == testString || str[editPos] != editByte {
		t.Errorf("str=%s, len=%d", str, len(str))
	}
}

func TestGoStringNull(t *testing.T) {
	str := GoString(nil)
	if len(str) > 0 {
		t.Errorf("expected empty string")
	}
}

func TestStringBuffer(t *testing.T) {
	str := "hello"
	buf := &StringBuffer{}

	if buf.CharPtr() != nil {
		t.Errorf("expected nil char pointer")
	}
	if len(buf.String()) > 0 {
		t.Errorf("expected empty string")
	}

	buf.Write(str)
	if buf.CharPtr() == nil {
		t.Errorf("expected non-nil char pointer")
	}
	if buf.String() != str {
		t.Errorf("string does not match: %s expected, but %s found", str, buf.String())
	}

	// test reallocation
	str = str + " world"
	buf.Write(str)
	if buf.String() != str {
		t.Errorf("string does not match: %s expected, but %s found", str, buf.String())
	}

	buf.Free()
}
