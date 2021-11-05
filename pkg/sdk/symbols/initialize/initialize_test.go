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

package initialize

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = errors.New("errTest")

type sampleInitialize struct {
	destroyCalled bool
	baseInit
	reqs        sdk.ExtractRequestPool
	stringerBuf ptr.StringBuffer
	progressBuf ptr.StringBuffer
}

func (s *sampleInitialize) ExtractRequests() sdk.ExtractRequestPool {
	return s.reqs
}

func (s *sampleInitialize) SetExtractRequests(reqs sdk.ExtractRequestPool) {
	s.reqs = reqs
}

func (s *sampleInitialize) StringerBuffer() sdk.StringBuffer {
	return &s.stringerBuf
}

func (s *sampleInitialize) ProgressBuffer() sdk.StringBuffer {
	return &s.progressBuf
}

func (s *sampleInitialize) Destroy() {
	s.destroyCalled = true
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
	var handle cgo.Handle
	var cStr ptr.StringBuffer
	cStr.Write("cStr")

	// panic
	assertPanic(t, func() {
		SetOnInit(nil)
	})

	// nil state
	SetOnInit(func(config string) (sdk.PluginState, error) {
		return nil, nil
	})
	handle = cgo.Handle(plugin_init((*_Ctype_char)(cStr.CharPtr()), &res))
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if handle.Value() != nil {
		t.Errorf("(value): expected %d, but found %d", unsafe.Pointer(nil), handle.Value())
	}
	handle.Delete()

	// error
	SetOnInit(func(config string) (sdk.PluginState, error) {
		return nil, errTest
	})
	handle = cgo.Handle(plugin_init((*_Ctype_char)(cStr.CharPtr()), &res))
	if res != sdk.SSPluginFailure {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginFailure, res)
	}
	val, ok := handle.Value().(sdk.LastError)
	if !ok {
		t.Errorf("(value): should implement sdk.LastError")
	} else if val.LastError() != errTest {
		t.Errorf("(err): expected %s, but found %s", errTest.Error(), val.LastError().Error())
	}
	handle.Delete()

	// success
	state := &sampleInitialize{}
	SetOnInit(func(config string) (sdk.PluginState, error) {
		return state, nil
	})
	handle = cgo.Handle(plugin_init((*_Ctype_char)(cStr.CharPtr()), &res))
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if handle.Value() != state {
		t.Errorf("(value): expected %d, but found %d", unsafe.Pointer(state), handle.Value())
	} else if state.ExtractRequests() == nil {
		t.Errorf("expected SetExtractRequests() to be called")
	}

	// destroy
	plugin_destroy(_Ctype_uintptr_t(handle))
	if !state.destroyCalled {
		t.Errorf("expected Destroy() to be called")
	}
}
