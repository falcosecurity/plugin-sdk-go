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

package lasterr

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = fmt.Errorf("test")

type sampleLastErr struct {
	lastErrBuf ptr.StringBuffer
	lastErr    error
}

func (s *sampleLastErr) LastError() error {
	return s.lastErr
}

func (s *sampleLastErr) SetLastError(err error) {
	s.lastErr = err
}

func (s *sampleLastErr) LastErrorBuffer() sdk.StringBuffer {
	return &s.lastErrBuf
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}

func TestLastErr(t *testing.T) {
	sample := &sampleLastErr{}
	defer sample.LastErrorBuffer().Free()
	sample.SetLastError(errTest)
	handle := cgo.NewHandle(sample)
	defer handle.Delete()

	cStr := plugin_get_last_error(_Ctype_uintptr_t(handle))
	errStr := ptr.GoString(unsafe.Pointer(cStr))

	if errTest.Error() != errStr {
		t.Fatalf("expected %s, but found %s", errTest.Error(), errStr)
	}
}

func TestLastErrPanic(t *testing.T) {
	handle := cgo.NewHandle(int64(0))
	defer handle.Delete()
	assertPanic(t, func() {
		plugin_get_last_error(_Ctype_uintptr_t(handle))
	})
}
