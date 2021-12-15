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

// This package exports the following C function:
// - ss_plugin_rc read(ss_plugin_t* s, ss_instance_t* h, uint8_t* buf, uint32_t n, uint32_t *nread)
//
// The exported read requires s and h to be handles of cgo.Handle from this SDK.
// The value of the s handle must implement the sdk.PluginState interface.
// The value of the h handle must implement the sdk.Reader interface.
//
// This function is part of the capture_plugin_info interface as defined in
// plugin_info.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package read

/*
#include "read.h"
*/
import "C"
import (
	"io"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export _plugin_read_go
func _plugin_read_go(pState C.uintptr_t, iState C.uintptr_t, buf *C.uint8_t, len uint32, nread *uint32) int32 {
	n, err := cgo.Handle(iState).Value().(sdk.Reader).Read(cgo.Handle(pState).Value(), (*[1 << 28]byte)(unsafe.Pointer(buf))[:len:len])
	*nread = uint32(n)
	if err != nil {
		switch err {
		case io.EOF, sdk.ErrEOF:
			return sdk.SSPluginEOF
		case sdk.ErrTimeout:
			return sdk.SSPluginTimeout
		default:
			cgo.Handle(pState).Value().(sdk.LastError).SetLastError(err)
			return sdk.SSPluginFailure
		}
	}
	return sdk.SSPluginSuccess
}

// used internally for unit testing
type unitTestCaseFunc func(name string, s cgo.Handle, h cgo.Handle, len uint32, expectedRes int, expectedNRead uint32)

// used internally to run the unit tests
func doUnitTest(t *testing.T, f func(doTest unitTestCaseFunc)) {
	// Test using the Go implementation.
	goUnitTestCaseFunc := func(
		name string,
		s cgo.Handle,
		h cgo.Handle,
		len uint32,
		expectedRes int,
		expectedRead uint32,
	) {
		buf := make([]byte, len)
		nread := uint32(0)
		res := _plugin_read_go(
			(C.uintptr_t)(s),
			(C.uintptr_t)(h),
			(*C.uint8_t)(&buf[0]),
			len,
			&nread,
		)
		if int32(res) != int32(expectedRes) {
			t.Errorf("(go-read-%s) expected res %d, but found %d", name, expectedRes, res)
		}
		if nread != expectedRead {
			t.Errorf("(go-read%s) expected nread %d, but found %d", name, expectedRead, nread)
		}
	}

	// Test using the underlying C implementation that uses optimized buffering.
	// This is supposed to behave in the same exact way as the Go implementation,
	// because we want the C middleware optimization to not change the semantics.
	cUnitTestCaseFunc := func(
		name string,
		s cgo.Handle,
		h cgo.Handle,
		len uint32,
		expectedRes int,
		expectedRead uint32,
	) {
		buf := make([]byte, len)
		nread := uint32(0)
		res := int32(C.plugin_read(
			unsafe.Pointer(uintptr(s)),
			unsafe.Pointer(uintptr(h)),
			(*C.uint8_t)(&buf[0]),
			(C.uint32_t)(len),
			(*C.uint32_t)(&nread),
		))
		if int32(res) != int32(expectedRes) {
			t.Errorf("(c-read-%s) expected res %d, but found %d", name, expectedRes, res)
		}
		if nread != expectedRead {
			t.Errorf("(c-read-%s) expected nread %d, but found %d", name, expectedRead, nread)
		}
	}

	// Run the tests
	f(goUnitTestCaseFunc)
	f(cUnitTestCaseFunc)
}
