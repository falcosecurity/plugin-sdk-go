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

// This package exports a C function plugin_get_last_error() which is used
// by the plugin framework to get the last error set by the plugin.
//
// In almost all cases, your plugin should import this module. The
// *only* case where your plugin should not import this module is when
// your plugin exports its own plugin_get_last_error manually.
package lasterr

/*
#include <stdint.h> // for uintptr_t
*/
import "C"
import (
	"errors"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var (
	errNoErrorInterface = errors.New(`cannot get error message: plugin instance does not implement "error" interface`)
)

//export plugin_get_last_error
func plugin_get_last_error(pInstance C.uintptr_t) *C.char {
	buf := cgo.Handle(pInstance).Value().(sdk.LastErrorBuffer).LastErrorBuffer()
	err, ok := cgo.Handle(pInstance).Value().(error)
	if !ok {
		lastErr, ok := cgo.Handle(pInstance).Value().(sdk.LastError)
		if !ok {
			err = errNoErrorInterface
		} else {
			err = lastErr.LastError()
		}
	}
	buf.Write(err.Error())
	return (*C.char)(buf.CharPtr())
}
