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

package main

import (
	"fmt"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
)

type MyPlugin struct {
	plugins.BasePlugin
}

func init() {
	extractor.Register(&MyPlugin{})
}

func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  999,
		Name:                "extractor-example",
		Description:         "An Extractor Plugin Example",
		Contact:             "github.com/falcosecurity/plugin-sdk-go/",
		Version:             "0.1.0",
		RequiredAPIVersion:  "0.2.0",
		ExtractEventSources: []string{"example"},
	}
}

func (m *MyPlugin) Init(config string) error {
	return nil
}

func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "example.ts", Display: "", Desc: "The current timestamp"},
	}
}

func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	switch req.FieldID() {
	case 0:
		req.SetU64Value(uint64(time.Now().UnixNano()))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

// // (optional)
// func (m *MyPlugin) Destroy() {

// }

func main() {}
