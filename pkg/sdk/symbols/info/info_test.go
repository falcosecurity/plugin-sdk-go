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

import (
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/stretchr/testify/assert"
)

var testStr = "test"
var testU32 = uint32(1)
var testStrSlice = []string{"hello", "world"}
var testversion = "2.0.0"

func TestInfo(t *testing.T) {
	var resU32 uint32
	var resStr string
	var expectedStr string

	SetId(testU32)
	resU32 = plugin_get_id()
	if resU32 != testU32 {
		t.Errorf("(id) expected %d, but found %d", testU32, resU32)
	}

	SetName(testStr)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_name()))
	if resStr != testStr {
		t.Errorf("(name) expected %s, but found %s", testStr, resStr)
	}

	SetDescription(testStr)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_description()))
	if resStr != testStr {
		t.Errorf("(description) expected %s, but found %s", testStr, resStr)
	}

	SetContact(testStr)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_contact()))
	if resStr != testStr {
		t.Errorf("(contact) expected %s, but found %s", testStr, resStr)
	}

	SetVersion(testStr)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_version()))
	if resStr != testStr {
		t.Errorf("(version) expected %s, but found %s", testStr, resStr)
	}

	SetRequiredAPIVersion(testversion)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_required_api_version()))
	if resStr != testversion {
		t.Errorf("(requiredApiVersion) expected %s, but found %s", testStr, resStr)
	}

	SetEventSource(testStr)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_event_source()))
	if resStr != testStr {
		t.Errorf("(eventSource) expected %s, but found %s", testStr, resStr)
	}

	// extractEventSources: nil
	expectedStr = "[]"
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_extract_event_sources()))
	if resStr != expectedStr {
		t.Errorf("(extractEventSources) expected %s, but found %s", testStr, resStr)
	}

	// extractEventSources: regular case (should output a json)
	b, err := json.Marshal(testStrSlice)
	if err != nil {
		t.Error(err)
	}
	expectedStr = string(b)
	SetExtractEventSources(testStrSlice)
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_extract_event_sources()))
	if resStr != expectedStr {
		t.Errorf("(extractEventSources) expected %s, but found %s", testStr, resStr)
	}

	// extractEventSources: empty string
	expectedStr = "[]"
	SetExtractEventSources([]string{})
	resStr = ptr.GoString(unsafe.Pointer(plugin_get_extract_event_sources()))
	if resStr != expectedStr {
		t.Errorf("(extractEventSources) expected %s, but found %s", testStr, resStr)
	}
}

func TestSemver(t *testing.T) {
	t.Run("success_check", func(t *testing.T) {
		version := "2.0.0"
		panicFunc := func() {
			SetRequiredAPIVersion(version)
		}
		assert.NotPanics(t, panicFunc)
	})

	t.Run("invalid_version", func(t *testing.T) {
		version := "invalid"
		errMsg := "Incorrect format. Expected: Semantic Versioning: X.Y.Z"
		panicFunc := func() {
			SetRequiredAPIVersion(version)
		}
		assert.PanicsWithValue(t, errMsg, panicFunc)
	})

	t.Run("incompatible_major_number", func(t *testing.T) {
		version := "3.0.0"
		errMsg := "Plugin SDK Go required API version incompatible major number. Expected: Major version should be equal to 2 but got 3"
		panicFunc := func() {
			SetRequiredAPIVersion(version)
		}
		assert.PanicsWithValue(t, errMsg, panicFunc)
	})

	t.Run("incompatible_minor_number", func(t *testing.T) {
		version := "2.1.0"
		errMsg := "Plugin SDK Go required API version incompatible minor number. Expected: Minor version should be less than/equal to 0 but got 1"
		panicFunc := func() {
			SetRequiredAPIVersion(version)
		}
		assert.PanicsWithValue(t, errMsg, panicFunc)
	})

	t.Run("incompatible_patch_number", func(t *testing.T) {
		version := "2.0.3"
		errMsg := "Plugin SDK Go required API version incompatible patch number. Expected: Patch version should be less than/equal to 0 but got 3"
		panicFunc := func() {
			SetRequiredAPIVersion(version)
		}
		assert.PanicsWithValue(t, errMsg, panicFunc)
	})
}
