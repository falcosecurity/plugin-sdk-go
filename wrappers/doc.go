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

// The functions in this package provide "wrappers" that make it
// easier to implement plugin functions like plugin_extract_fields,
// plugin_next, and plugin_next_batch in Go. They primarily take
// function arguments that interact with go types and take care of the
// conversion from/to C types, iterating over C structs, etc.
//
// Including this package will automatically define the plugin api
// function plugin_extract_fields(). In turn, that C function will
// call go-specific functions that work on go types and take care of
// the details of type conversion for the plugin.
//
// If https://github.com/golang/go/issues/13467 were fixed, this
// function signature could directly use the C functions (and their C
// types) used by the API. Since we can't, we use go native types
// instead and change their return values to be more golang-friendly.
package wrappers
