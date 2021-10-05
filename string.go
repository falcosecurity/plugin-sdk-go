package sdk

import (
	"reflect"
	"unsafe"
)

const (
	cStringNullTerminator = byte(0)
)

// GoString converts a C string to a Go string. This is analoguous
// to C.GoString, but avoids unnecessary memory allcations and copies.
// The string length is determined by invoking strlen on the passed
// memory pointer.
// Note that the returned string is an aliased view of the underlying
// C-allocated memory. As such, writing inside the memory will cause
// the string contents to change. Accordingly, unsafe memory management,
// such as unexpectedly free-ing the underlying C memory, can cause
// non-deterministic behavior on the Go routines using the returned string.
func GoString(charPtr unsafe.Pointer) string {
	if charPtr == nil {
		return ""
	}

	// We manually implement strlen to avoid an unnecessary Go -> C call.
	// See: https://github.com/torvalds/linux/blob/f6274b06e326d8471cdfb52595f989a90f5e888f/lib/string.c#L558
	var len int
	for len = 0; *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(charPtr)) + uintptr(len))) != cStringNullTerminator; len++ {
		// nothing
	}

	var res string
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Data = uintptr(charPtr)
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Len = len
	return res
}
