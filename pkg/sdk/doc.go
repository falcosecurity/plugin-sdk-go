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

// This package provides support code for developers that would like
// to write Falcosecurity Plugins (https://falco.org/docs/plugins/) in
// Go. It provides consts/go structs for C values/structs used by the
// plugins API, functions to create plugin and instance state, and
// wrapping functions that allow for easy batch event injection and
// asynchronous field extraction.
//
// Before using this package, review the developer's guide (https://falco.org/docs/plugins/developers_guide/) which fully documents the API and provides best practices for writing plugins. The developer's guide includes a walkthrough (https://falco.org/docs/plugins/developers_guide/#example-go-plugin-dummy) of a plugin written in Go that uses this package.
package sdk
