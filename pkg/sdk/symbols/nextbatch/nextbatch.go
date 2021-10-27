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

package nextbatch

/*
#include "../../plugin_info.h"
*/
import "C"
import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_next_batch
func plugin_next_batch(pState C.uintptr_t, iState C.uintptr_t, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
	iHandle := cgo.Handle(iState)
	pHandle := cgo.Handle(pState)
	events := iHandle.Value().(sdk.Events).Events()
	var err error
	var n int

	nextBatch, ok := iHandle.Value().(sdk.NextBatcher)
	if ok {
		n, err = nextBatch.NextBatch(pHandle.Value().(sdk.PluginState), events)
	} else {
		next := iHandle.Value().(sdk.Nexter)
		for n = 0; err == nil && n < events.Len(); n++ {
			events.Get(n).SetTimestamp(C.UINT64_MAX)
			err = next.Next(pHandle.Value().(sdk.PluginState), events.Get(n))
		}
	}

	*nevts = uint32(n)
	*retEvts = (*C.ss_plugin_event)(events.ArrayPtr())
	switch err {
	case sdk.ErrEOF:
		return sdk.SSPluginEOF
	case sdk.ErrTimeout:
		return sdk.SSPluginTimeout
	case nil:
		return sdk.SSPluginSuccess
	default:
		*nevts = uint32(0)
		*retEvts = nil
		cgo.Handle(pState).Value().(sdk.LastError).SetLastError(err)
		return sdk.SSPluginFailure
	}
}
