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

package open

/*
#include <stdint.h>
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var (
	onOpenFn OnOpenFn
)

type OnOpenFn func(config string) (sdk.InstanceState, error)

func SetOnOpen(fn OnOpenFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/open.SetOnOpen: fn must not be nil")
	}
	onOpenFn = fn
}

//export plugin_open
func plugin_open(plgState C.uintptr_t, params *C.char, rc *int32) C.uintptr_t {
	if onOpenFn == nil {
		panic("plugin-sdk-go/sdk/symbols/open: SetOnOpen must be called")
	}

	iState, err := onOpenFn(C.GoString(params))
	if err == nil {
		// this allows a nil iState
		iEvents, ok := iState.(sdk.Events)
		if ok && iEvents.Events() == nil {
			var events sdk.EventWriters
			events, err = sdk.NewEventWriters(int64(sdk.MaxNextBatchEvents), int64(sdk.MaxEvtSize))
			if err == nil {
				iEvents.SetEvents(events)
			}
		}
	}

	if err != nil {
		cgo.Handle(plgState).Value().(sdk.LastError).SetLastError(err)
		*rc = sdk.SSPluginFailure
		return 0
	}
	*rc = sdk.SSPluginSuccess
	return (C.uintptr_t)(cgo.NewHandle(iState))
}

//export plugin_close
func plugin_close(plgState C.uintptr_t, instanceState C.uintptr_t) {
	if instanceState != 0 {
		handle := cgo.Handle(instanceState)
		if state, ok := handle.Value().(sdk.Closer); ok {
			state.Close()
		}
		if state, ok := handle.Value().(sdk.Events); ok {
			state.Events().Free()
		}
		handle.Delete()
	}
}
