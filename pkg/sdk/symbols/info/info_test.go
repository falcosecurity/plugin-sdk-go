// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
	"fmt"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/stretchr/testify/assert"
)

var testStr = "test"
var testU32 = uint32(1)
var testStrSlice = []string{"hello", "world"}

func testFormatVer(major, minor, patch int) string {
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func TestInfo(t *testing.T) {
	var resU32 uint32
	var resStr string
	var expectedStr string

	SetId(testU32)
	resU32 = plugin_get_id()
	if resU32 != testU32 {
		t.Errorf("(plugin id) expected %d, but found %d", testU32, resU32)
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

func TestSplitVersionString(t *testing.T) {
	t.Run("invalid version string 1", func(t *testing.T) {
		panicFunc := func() {
			splitVersionString("2..1..2")
		}
		assert.Panics(t, panicFunc)
	})

	t.Run("invalid version string 2", func(t *testing.T) {
		panicFunc := func() {
			splitVersionString("2.2.3..32")
		}
		assert.Panics(t, panicFunc)
	})

	t.Run("invalid version string 3", func(t *testing.T) {
		panicFunc := func() {
			splitVersionString("2.2.3.")
		}
		assert.Panics(t, panicFunc)
	})

	t.Run("invalid version string 4", func(t *testing.T) {
		panicFunc := func() {
			splitVersionString("2..2.3")
		}
		assert.Panics(t, panicFunc)
	})

	t.Run("valid version string", func(t *testing.T) {
		panicFunc := func() {
			splitVersionString("2.2.3")
		}
		assert.NotPanics(t, panicFunc)
	})

	t.Run("check split version string", func(t *testing.T) {
		major, minor, patch := splitVersionString("2.4.3")
		if major != "2" {
			t.Errorf("(Major) expected %s, but found %s", "2", major)
		}
		if minor != "4" {
			t.Errorf("(Minor) expected %s, but found %s", "4", minor)
		}
		if patch != "3" {
			t.Errorf("(Patch) expected %s, but found %s", "3", patch)
		}
	})
}

func TestSemver(t *testing.T) {
	// Get the SDK required version
	// we set an empty string to obtain the default SDK version
	SetRequiredAPIVersion("")
	versionSDK := ptr.GoString(unsafe.Pointer(plugin_get_required_api_version()))
	var majorSDK, minorSDK, patchSDK int
	nums, err := fmt.Sscanf(versionSDK, "%d.%d.%d", &majorSDK, &minorSDK, &patchSDK)
	if nums != 3 || err != nil {
		t.Errorf("Unable to obtain the default SDK version")
	}

	// plguin Major == SDK Major && plguin Minor == SDK Minor && plguin Patch == SDK Patch
	t.Run("plguin Major == SDK Major && plguin Minor == SDK Minor && plguin Patch == SDK Patch", func(t *testing.T) {
		SetRequiredAPIVersion(testFormatVer(majorSDK, minorSDK, patchSDK))
		requiredAPIVersion := ptr.GoString(unsafe.Pointer(plugin_get_required_api_version()))
		expectedRequiredAPIVersion := testFormatVer(majorSDK, minorSDK, patchSDK)
		if expectedRequiredAPIVersion != requiredAPIVersion {
			t.Errorf("(requiredApiVersion) expected %s, but found %s", expectedRequiredAPIVersion, requiredAPIVersion)
		}
	})

	// plguin Major > SDK Major
	t.Run("plguin Major > SDK Major", func(t *testing.T) {
		panicFunc := func() {
			SetRequiredAPIVersion(testFormatVer(majorSDK+1, minorSDK, patchSDK))
		}
		assert.PanicsWithValue(t, fmt.Sprintf("Incompatible required Major version between SDK and the plugin. Major SDK version is equal to %d but the plugin uses %d. The 2 Major versions should be equal.", majorSDK, majorSDK+1), panicFunc)
	})

	// plguin Major == SDK Major && plguin Minor > SDK Minor
	t.Run("plguin Major == SDK Major && plguin Minor > SDK Minor", func(t *testing.T) {
		panicFunc := func() {
			SetRequiredAPIVersion(testFormatVer(majorSDK, minorSDK+1, patchSDK))
		}
		assert.PanicsWithValue(t, fmt.Sprintf("The plugin requires a Minor version greater than the SDK one. Minor SDK version is equal to %d but the plugin uses %d. The plugin should always require a Minor version lower or equal to the SDK one.", minorSDK, minorSDK+1), panicFunc)
	})

	// plguin Major == SDK Major && plguin Minor == SDK Minor && plguin Patch > SDK Patch
	t.Run("plguin Major == SDK Major && plguin Minor == SDK Minor && plguin Patch > SDK Patch", func(t *testing.T) {
		panicFunc := func() {
			SetRequiredAPIVersion(testFormatVer(majorSDK, minorSDK, patchSDK+1))
		}
		assert.PanicsWithValue(t, fmt.Sprintf("The plugin requires a Patch version greater than the SDK one. Patch SDK version is equal to %d but the plugin uses %d. The plugin should always require a Patch version lower or equal to the SDK one.", patchSDK, patchSDK+1), panicFunc)
	})

	t.Run("empty plugin version", func(t *testing.T) {
		// This should set as default the SDK required version since we don't provide the required plugin version
		SetRequiredAPIVersion("")
		requiredAPIVersion := ptr.GoString(unsafe.Pointer(plugin_get_required_api_version()))
		expectedRequiredAPIVersion := testFormatVer(majorSDK, minorSDK, patchSDK)
		if expectedRequiredAPIVersion != requiredAPIVersion {
			t.Errorf("(requiredApiVersion) expected %s, but found %s", expectedRequiredAPIVersion, requiredAPIVersion)
		}
	})
}
