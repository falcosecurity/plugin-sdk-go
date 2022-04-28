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

package extractor

import (
	"fmt"
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
)

type testPlugin struct {
	plugins.BasePlugin
}

func (m *testPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  999,
		Name:                "test",
		Description:         "Extractor Test",
		Contact:             "",
		Version:             "",
		RequiredAPIVersion:  "",
		ExtractEventSources: []string{"test"},
	}
}

func (m *testPlugin) Init(config string) error {
	return nil
}

func (m *testPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "test.field", Display: "Test Field", Desc: "Test Field"},
	}
}

func (m *testPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	switch req.FieldID() {
	case 0:
		req.SetValue(uint64(0))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}
