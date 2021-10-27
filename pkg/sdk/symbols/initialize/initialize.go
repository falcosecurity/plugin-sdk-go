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

/*
#include <stdint.h>
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

type baseInit struct {
	lastErr    error
	lastErrBuf ptr.StringBuffer
}

func (b *baseInit) LastError() error {
	return b.lastErr
}

func (b *baseInit) SetLastError(err error) {
	b.lastErr = err
}

func (b *baseInit) LastErrorBuffer() sdk.StringBuffer {
	return &b.lastErrBuf
}

type OnInitFn func(config string) (sdk.PluginState, error)

var (
	onInitFn OnInitFn = func(config string) (sdk.PluginState, error) { return &baseInit{}, nil }
)

func SetOnInit(fn OnInitFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/initialize.SetOnInit: fn must not be nil")
	}
	onInitFn = fn
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) C.uintptr_t {
	var state sdk.PluginState
	var err error

	state, err = onInitFn(C.GoString(config))
	if err != nil {
		state = &baseInit{}
		state.(sdk.LastError).SetLastError(err)
		*rc = sdk.SSPluginFailure
	} else {
		// this allows a nil state
		extrReqs, ok := state.(sdk.ExtractRequests)
		if ok && extrReqs.ExtractRequests() == nil {
			extrReqs.SetExtractRequests(sdk.NewExtractRequestPool())
		}
		*rc = sdk.SSPluginSuccess
	}

	return (C.uintptr_t)(cgo.NewHandle(state))
}

//export plugin_destroy
func plugin_destroy(pState C.uintptr_t) {
	if pState != 0 {
		handle := cgo.Handle(pState)
		if state, ok := handle.Value().(sdk.Destroyer); ok {
			state.Destroy()
		}
		if state, ok := handle.Value().(sdk.ExtractRequests); ok {
			state.ExtractRequests().Free()
		}
		if state, ok := handle.Value().(sdk.LastErrorBuffer); ok {
			state.LastErrorBuffer().Free()
		}
		if state, ok := handle.Value().(sdk.StringerBuffer); ok {
			state.StringerBuffer().Free()
		}
		if state, ok := handle.Value().(sdk.ProgressBuffer); ok {
			state.ProgressBuffer().Free()
		}

		handle.Delete()
	}
}
