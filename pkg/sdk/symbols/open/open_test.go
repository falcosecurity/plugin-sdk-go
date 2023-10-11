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

package open

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = errors.New("errTest")

type sampleOpen struct {
	lastErr error
}

func (b *sampleOpen) LastError() error {
	return b.lastErr
}

func (b *sampleOpen) SetLastError(err error) {
	b.lastErr = err
}

type sampleOpenInstance struct {
	closeCalled bool
	events      sdk.EventWriters
}

func (s *sampleOpenInstance) Events() sdk.EventWriters {
	return s.events
}

func (s *sampleOpenInstance) SetEvents(evts sdk.EventWriters) {
	s.events = evts
}

func (s *sampleOpenInstance) Close() {
	s.closeCalled = true
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}

func TestInitialize(t *testing.T) {
	var res int32
	var pHandle cgo.Handle
	var iHandle cgo.Handle
	var cStr ptr.StringBuffer

	// panics
	assertPanic(t, func() {
		SetOnOpen(nil)
	})
	assertPanic(t, func() {
		plugin_open((_Ctype_uintptr_t)(pHandle), (*_Ctype_char)(cStr.CharPtr()), &res)
	})

	// initilize
	pState := &sampleOpen{}
	pHandle = cgo.NewHandle(pState)
	cStr.Write("cStr")

	// nil state
	SetOnOpen(func(config string) (sdk.InstanceState, error) {
		return nil, nil
	})
	iHandle = cgo.Handle(plugin_open((_Ctype_uintptr_t)(pHandle), (*_Ctype_char)(cStr.CharPtr()), &res))
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if iHandle.Value() != nil {
		t.Errorf("(value): expected %d, but found %d", unsafe.Pointer(nil), iHandle.Value())
	}
	iHandle.Delete()

	// error
	SetOnOpen(func(config string) (sdk.InstanceState, error) {
		return nil, errTest
	})
	iHandle = cgo.Handle(plugin_open((_Ctype_uintptr_t)(pHandle), (*_Ctype_char)(cStr.CharPtr()), &res))
	if res != sdk.SSPluginFailure {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginFailure, res)
	} else if pState.LastError() != errTest {
		t.Errorf("(err): expected %s, but found %s", errTest.Error(), pState.LastError().Error())
	}

	// success
	iState := &sampleOpenInstance{}
	SetOnOpen(func(config string) (sdk.InstanceState, error) {
		return iState, nil
	})
	iHandle = cgo.Handle(plugin_open((_Ctype_uintptr_t)(pHandle), (*_Ctype_char)(cStr.CharPtr()), &res))
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if iHandle.Value() != iState {
		t.Errorf("(value): expected %d, but found %d", unsafe.Pointer(iState), iHandle.Value())
	} else if iState.Events() == nil {
		t.Errorf("expected SetEvents() to be called")
	}

	// close
	plugin_close(_Ctype_uintptr_t(pHandle), _Ctype_uintptr_t(iHandle))
	if !iState.closeCalled {
		t.Errorf("expected Close() to be called")
	}
	pHandle.Delete()
}
