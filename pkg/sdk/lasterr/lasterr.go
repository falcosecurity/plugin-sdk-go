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

package lasterr

/*
#include <stdlib.h>
#include <stdint.h> // for uintptr_t
*/
import "C"
import (
	"errors"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
)

var (
	errNoErrorInterface = errors.New(`cannot get error message: plugin instance does not implement "error" interface`)
)

//export plugin_get_last_error
func plugin_get_last_error(pInstance C.uintptr_t) *C.char {
	err, ok := cgo.Handle(pInstance).Value().(error)
	if !ok {
		err = errNoErrorInterface
	}
	return C.CString(err.Error())
}
