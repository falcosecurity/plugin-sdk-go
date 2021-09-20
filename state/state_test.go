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

package state_test

import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/state"
)

var plgState unsafe.Pointer

func ExampleNewStateContainer() (unsafe.Pointer) {

	type pluginState struct {
		// State for a created plugin goes here
	}

	// Inside plugin_init(config *C.char, rc *int32) unsafe.Pointer) {
	sobj := state.NewStateContainer()
	pCtx := &pluginState{}
	state.SetContext(sobj, unsafe.Pointer(pCtx))
	return sobj
	// }
}

func ExampleSetContext() (unsafe.Pointer) {

	type pluginState struct {
		// State for a created plugin goes here
	}

	// Inside plugin_init(config *C.char, rc *int32) unsafe.Pointer) {
	sobj := state.NewStateContainer()
	pCtx := &pluginState{}
	state.SetContext(sobj, unsafe.Pointer(pCtx))
	return sobj
	// }
}

func ExampleContext() (string) {

	type pluginState struct {
		// State for a created plugin goes here
		lastError       string
	}

	// Inside plugin_get_last_error(plgState unsafe.Pointer) *C.char {
	pCtx := (*pluginState)(state.Context(plgState))
	// Can now access pCtx as a pluginState struct
	return pCtx.lastError
	// }
}

func ExampleFree() {
	// inside plugin_destroy(plgState unsafe.Pointer) {
	state.Free(plgState)
	// }
}

