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

// This package contains utilities for passing pointers to go managed
// memory to/from the plugins framework. This allows using go structs
// to represent the state of a created plugin (e.g. ss_plugin_t) or
// the state of an open plugin instance (e.g. ss_instance_t), without
// having those structs be garbage collected after a given go
// plugin_XXX function has returned.
//
// Here's an overview of how to use the functions:
//
//    type pluginState struct {
//        // State for a created plugin goes here
//    }
//
//    // export plugin_init
//    func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
//
//        sobj := state.NewStateContainer()
//
//        // Allocate the context struct attach it to the state
//        pCtx := &pluginState{}
//        state.SetContext(sobj, unsafe.Pointer(pCtx))
//
//        *rc = sdk.ScapSuccess
//        return sobj
//    }
//
//    //export plugin_destroy
//    func plugin_destroy(plgState unsafe.Pointer) {
//        state.Free(plgState)
//    }
//
// When go 1.17 is more widespread, this implementation will change to
// use cgo.Handle (https://pkg.go.dev/runtime/cgo@go1.17#Handle)
// instead.
package state

