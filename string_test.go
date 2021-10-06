package sdk

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
