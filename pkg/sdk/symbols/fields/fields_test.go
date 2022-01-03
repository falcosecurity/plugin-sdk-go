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

package fields

import (
	"encoding/json"
	"testing"
	"reflect"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var sampleFields = []sdk.FieldEntry{
	{Type: "uint64", Name: "test.field", Display: "Test Field", Desc: "Test Field"},
}

func TestFields(t *testing.T) {
	// Test get/set
	if Fields() != nil {
		t.Errorf("expected nil")
	}
	SetFields(sampleFields)
	if len(Fields()) != len(sampleFields) {
		t.Errorf("expected %d, but found %d", len(sampleFields), len(Fields()))
	}
	for i, f := range Fields() {
		if ! reflect.DeepEqual(f, sampleFields[i]) {
			t.Errorf("wrong sample at index %d", i)
		}
	}

	// Test C symbol
	b, err := json.Marshal(&sampleFields)
	if err != nil {
		t.Error(err)
	}
	cStr := plugin_get_fields()
	str := ptr.GoString(unsafe.Pointer(cStr))
	if str != string(b) {
		t.Errorf("expected %s, but found %s", string(b), str)
	}
}
