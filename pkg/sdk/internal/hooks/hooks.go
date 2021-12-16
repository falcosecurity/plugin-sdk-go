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

// Package hooks contains a set of init/destroy related hooks to meant
// to be used internally in the SDK.
package hooks

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
)

// OnDestroyFn is a callback used in plugin_destroy.
type OnDestroyFn func(handle cgo.Handle)

var onDestroy OnDestroyFn = func(cgo.Handle) {}

// SetOnDestroy sets an deinitialization callback to be called in plugin_destroy to
// release some resources the plugin state.
func SetOnDestroy(fn OnDestroyFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/initialize.SetOnDestroy: fn must not be nil")
	}
	onDestroy = fn
}

// OnDestroy returns the currently set deinitialization callback to
// be called in plugin_destroy
func OnDestroy() OnDestroyFn {
	return onDestroy
}
