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

package initschema

import (
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var sampleSchema = &sdk.SchemaInfo{
	Schema: "",
}

func TestInitSchema(t *testing.T) {
	var schemaType _Ctype_ss_plugin_schema_type
	var schemaStr *_Ctype_char

	// Test with nil schema
	if InitSchema() != nil {
		t.Errorf("expected nil")
	}
	schemaStr = plugin_get_init_schema(&schemaType)
	if len(ptr.GoString(unsafe.Pointer(schemaStr))) > 0 {
		t.Errorf("expected empty string, but found %s", ptr.GoString(unsafe.Pointer(schemaStr)))
	}
	if schemaType != _Ciconst_SS_PLUGIN_SCHEMA_NONE {
		t.Errorf("expected %d, but found %d", _Ciconst_SS_PLUGIN_SCHEMA_NONE, schemaType)
	}

	// Test with non-nil schema
	SetInitSchema(sampleSchema)
	if InitSchema() != sampleSchema {
		t.Errorf("expected %p, but found %p", InitSchema(), sampleSchema)
	}
	schemaStr = plugin_get_init_schema(&schemaType)
	if ptr.GoString(unsafe.Pointer(schemaStr)) != sampleSchema.Schema {
		t.Errorf("expected %s, but found %s", sampleSchema.Schema, ptr.GoString(unsafe.Pointer(schemaStr)))
	}
	if schemaType != _Ciconst_SS_PLUGIN_SCHEMA_JSON {
		t.Errorf("expected %d, but found %d", _Ciconst_SS_PLUGIN_SCHEMA_JSON, schemaType)
	}
}
