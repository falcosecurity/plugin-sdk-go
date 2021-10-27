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

package evtstr

/*
#include <stdint.h>
*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_event_to_string
func plugin_event_to_string(pState C.uintptr_t, data *C.uint8_t, datalen uint32) *C.char {
	pHandle := cgo.Handle(pState)
	evtStringer := pHandle.Value().(sdk.Stringer)
	buf := pHandle.Value().(sdk.StringerBuffer).StringerBuffer()
	brw, err := ptr.NewBytesReadWriter(unsafe.Pointer(data), int64(datalen), int64(datalen))

	if err != nil {
		buf.Write(err.Error())
	} else {
		if str, err := evtStringer.String(brw); err == nil {
			buf.Write(str)
		} else {
			buf.Write(err.Error())
		}
	}

	return (*C.char)(buf.CharPtr())
}