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

package progress

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var testPct = float64(0.45)

type sampleProgress struct {
	strBuf ptr.StringBuffer
	pct    float64
}

func (s *sampleProgress) ProgressBuffer() sdk.StringBuffer {
	return &s.strBuf
}

func formatPercent(pct float64) string {
	return fmt.Sprintf("%.2f", pct*100)
}

func (s *sampleProgress) Progress(pState sdk.PluginState) (float64, string) {
	return s.pct, formatPercent(s.pct)
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}

func TestProgress(t *testing.T) {
	var resPct uint32
	var resStr string
	var expectedStr string

	sample := &sampleProgress{}
	defer sample.ProgressBuffer().Free()
	pHandle := cgo.NewHandle(1)
	iHandle := cgo.NewHandle(sample)
	defer pHandle.Delete()
	defer iHandle.Delete()

	// test success
	sample.pct = testPct
	expectedStr = formatPercent(testPct)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_progress(_Ctype_uintptr_t(pHandle), _Ctype_uintptr_t(iHandle), &resPct)))
	if resStr != expectedStr {
		t.Errorf("expected %s, but found %s", expectedStr, resStr)
	}
	if resPct != uint32(testPct*10000) {
		t.Errorf("expected %d, but found %d", uint32(testPct*10000), resPct)
	}
}

func TestProgressPanic(t *testing.T) {
	var resPct uint32
	handle := cgo.NewHandle(int64(0))
	defer handle.Delete()
	assertPanic(t, func() {
		plugin_get_progress(_Ctype_uintptr_t(handle), _Ctype_uintptr_t(handle), &resPct)
	})
}
