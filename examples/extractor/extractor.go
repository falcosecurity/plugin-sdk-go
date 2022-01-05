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

// This plugin is a simple example of extractor plugin.
// The plugin extracts the "example.ts" field from the "example" event source,
// which simply represents the timestamp of the extraction.
package main

import (
	"fmt"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
)

// Defining a type for the plugin.
// Composing the struct with plugins.BasePlugin is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in the plugin must be defined here.
// In this simple example, we don't need any state.
type MyPlugin struct {
	plugins.BasePlugin
}

// The plugin must be registered to the SDK in the init() function.
// The extractor.Register function initializes our plugin as an extractor
// plugin. This requires our plugin to implement the extractor.Plugin
// interface, so compilation will fail if the mandatory methods are not
// implemented.
func init() {
	extractor.Register(&MyPlugin{})
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory for extractor plugins.
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

// Init initializes this plugin with a given config string, which is unused
// in this example. This method is mandatory for extractor plugins.
func (m *MyPlugin) Init(config string) error {
	return nil
}

// Fields return the list of extractor fields exported by this plugin.
// This method is mandatory for extractor plugins.
func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "example.ts", Display: "Current Timestamp", Desc: "The current timestamp"},
	}
}

// Extract extracts the value of a single field from a given event data.
// This method is mandatory for extractor plugins.
func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	switch req.FieldID() {
	case 0:
		req.SetValue(uint64(time.Now().UnixNano()))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

// Destroy is gets called by the SDK when the plugin gets deinitialized.
// This is useful to release any open resource used by the plugin.
// This method is optional for extractor plugins.
// func (m *MyPlugin) Destroy() {
//
// }

// InitSchema is gets called by the SDK before initializing the plugin.
// This returns a schema representing the configuration expected by the
// plugin to be passed to the Init() method. Defining InitSchema() allows
// the framework to automatically validate the configuration, so that the
// plugin can assume that it to be always be well-formed when passed to Init().
// This is ignored if the return value is nil. The returned schema must follow
// the JSON Schema specific. See: https://json-schema.org/
// This method is optional for extractor plugins.
// func (m *MyPlugin) InitSchema() *sdk.SchemaInfo {
//
// }

func main() {}
