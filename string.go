package sdk

import (
	"reflect"
	"unsafe"
)

/*
#include <string.h>
*/
import "C"

func GoString(charPtr unsafe.Pointer) string {
	if charPtr == nil {
		return ""
	}
	len := int(C.strlen((*C.char)(charPtr)))
	var res string
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Data = uintptr(charPtr)
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Len = len
	return res
}
