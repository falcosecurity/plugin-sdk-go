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

package info

/*
#include <stdlib.h>
*/
import "C"

var (
	pType                uint32
	pId                  uint32
	pName                string
	pDescription         string
	pContact             string
	pVersion             string
	pRequiredAPIVersion  string
	pEventSource         string
	pExtractEventSources string
)

//export plugin_get_type
func plugin_get_type() uint32 {
	return pType
}

func SetType(t uint32) {
	pType = t
}

//export plugin_get_id
func plugin_get_id() uint32 {
	return pId
}

func SetId(id uint32) {
	pId = id
}

//export plugin_get_name
func plugin_get_name() *C.char {
	return C.CString(pName)
}

func SetName(name string) {
	pName = name
}

//export plugin_get_description
func plugin_get_description() *C.char {
	return C.CString(pDescription)
}

func SetDescription(desc string) {
	pDescription = desc
}

//export plugin_get_contact
func plugin_get_contact() *C.char {
	return C.CString(pContact)
}

func SetContact(contact string) {
	pContact = contact
}

//export plugin_get_version
func plugin_get_version() *C.char {
	return C.CString(pVersion)
}

func SetVersion(version string) {
	pVersion = version
}

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(pRequiredAPIVersion)
}

func SetRequiredAPIVersion(apiVer string) {
	pRequiredAPIVersion = apiVer
}

//export plugin_get_event_source
func plugin_get_event_source() *C.char {
	return C.CString(pEventSource)
}

func SetEventSource(source string) {
	pEventSource = source
}

//export plugin_get_extract_event_sources
func plugin_get_extract_event_sources() *C.char {
	return C.CString(pExtractEventSources)
}

func SetExtractEventSource(source string) {
	pExtractEventSources = source
}
