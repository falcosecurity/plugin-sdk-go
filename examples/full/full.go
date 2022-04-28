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

// This plugin is a simple example of plugin with both event sourcing and
// field extraction capabilities.
// The plugin produces events of the "example" data source containing
// a single uint64 representing the incrementing value of a counter,
// serialized using a encoding/gob encoder. The plugin is capable of
// extracting the "example.count" and "example.countstr" fields from the
// "example" event source, which are simple numeric and string representations
// of the counter value.
package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// Defining a type for the plugin configuration.
// In this simple example, users can define the starting value the event
// counter. the `jsonschema` tags is used to automatically generate a
// JSON Schema definition, so that the framework can perform automatic
// validations.
type MyPluginConfig struct {
	Start uint64 `json:"start" jsonschema:"title=start value,description=The starting value of each counter"`
}

// Defining a type for the plugin.
// Composing the struct with plugins.BasePlugin is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in the plugin must be defined here.
type MyPlugin struct {
	plugins.BasePlugin
	config MyPluginConfig
}

// Defining a type for the plugin source capture instances returned by Open().
// Multiple instances of the same plugin can be opened at the same time for
// different capture sessions.
// Composing the struct with plugins.BaseInstance is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in each plugin instance must be defined here.
// In this example, we store the internal value of the incrementing counter.
type MyInstance struct {
	source.BaseInstance
	counter uint64
}

// The plugin must be registered to the SDK in the init() function.
// Registering the plugin using both source.Register and extractor.Register
// declares to the SDK a plugin with both sourcing and extraction features
// enabled. The order in which the two Register functions are called is not
// relevant.
// This requires our plugin to implement the source.Plugin interface, so
// compilation will fail if the mandatory methods are not implemented.
func init() {
	p := &MyPlugin{}
	extractor.Register(p)
	source.Register(p)
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory.
func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "full-example",
		Description: "A Plugin Example for both Source and Extraction",
		Contact:     "github.com/falcosecurity/plugin-sdk-go/",
		Version:     "0.1.0",
		EventSource: "example",
	}
}

// InitSchema is gets called by the SDK before initializing the plugin.
// This returns a schema representing the configuration expected by the
// plugin to be passed to the Init() method. Defining InitSchema() allows
// the framework to automatically validate the configuration, so that the
// plugin can assume that it to be always be well-formed when passed to Init().
// This is ignored if the return value is nil. The returned schema must follow
// the JSON Schema specific. See: https://json-schema.org/
// This method is optional.
func (m *MyPlugin) InitSchema() *sdk.SchemaInfo {
	// We leverage the jsonschema package to autogenerate the
	// JSON Schema definition using reflection from our config struct.
	schema, err := jsonschema.Reflect(&MyPluginConfig{}).MarshalJSON()
	if err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init initializes this plugin with a given config string.
// Since this plugin defines the InitSchema() method, we can assume
// that the configuration is pre-validated by the framework and
// always well-formed according to the provided schema.
// This method is mandatory.
func (m *MyPlugin) Init(config string) error {
	// Deserialize the config json. Ignoring the error
	// and not validating the config values is possible
	// due to the schema defined through InitSchema(),
	// for which the framework performas a pre-validation.
	json.Unmarshal([]byte(config), &m.config)
	return nil
}

// Fields return the list of extractor fields exported by this plugin.
// This method is mandatory the field extraction capability.
// If the Fields method is defined, the framework expects an Extract method
// to be specified too.
func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "example.count", Display: "Counter value", Desc: "Current value of the internal counter"},
		{Type: "string", Name: "example.countstr", Display: "Counter string value", Desc: "String represetation of current value of the internal counter"},
	}
}

// This method is mandatory the field extraction capability.
// If the Extract method is defined, the framework expects an Fields method
// to be specified too.
func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var value uint64
	encoder := gob.NewDecoder(evt.Reader())
	if err := encoder.Decode(&value); err != nil {
		return err
	}

	switch req.FieldID() {
	case 0:
		req.SetValue(value)
		return nil
	case 1:
		req.SetValue(fmt.Sprintf("%d", value))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

// OpenParams returns a list of suggested parameters that would be accepted
// as valid arguments to Open().
// This method is optional for the event sourcing capability.
func (m *MyPlugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{
			Value: "file:///hello-world.bin",
			Desc:  "A resource that can be opened by this plugin. This is not used here and just serves an example.",
		},
	}, nil
}

// Open opens the plugin source and starts a new capture session (e.g. stream
// of events), creating a new plugin instance. The state of each instance can
// be initialized here. This method is mandatory for the event sourcing capability.
func (m *MyPlugin) Open(params string) (source.Instance, error) {
	// An event batch buffer can optionally be defined to specify custom
	// values for max data size or max batch size. If nothing is set
	// with the SetEvents method, the SDK will provide a default value
	// after the Open method returns.
	// In this example, we want to allocate a batch of max 10 events, each
	// one of max 64 bytes, which is more than enough to host the serialized
	// incrementing counter value.
	myBatch, err := sdk.NewEventWriters(10, 64)
	if err != nil {
		return nil, err
	}

	myInstance := &MyInstance{
		counter: m.config.Start,
	}
	myInstance.SetEvents(myBatch)
	return myInstance, nil
}

// String produces a string representation of an event data produced by the
// event source of this plugin.
// This method is optional for the event sourcing capability.
func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	var value uint64
	encoder := gob.NewDecoder(in)
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("counter: %d", value), nil
}

// NextBatch produces a batch of new events, and is called repeatedly by the
// framework. For plugins with event sourcing capability, it's mandatory to
// specify a NextBatch method.
// The batch has a maximum size that dependes on the size of the underlying
// reusable memory buffer. A batch can be smaller than the maximum size.
func (m *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	var n int
	var evt sdk.EventWriter
	for n = 0; n < evts.Len(); n++ {
		evt = evts.Get(n)
		m.counter++
		encoder := gob.NewEncoder(evt.Writer())
		if err := encoder.Encode(m.counter); err != nil {
			return 0, err
		}
		evt.SetTimestamp(uint64(time.Now().UnixNano()))
	}
	return n, nil
}

// Progress returns a percentage indicator referring to the production progress
// of the event source of this plugin.
// This method is optional for the event sourcing capability.
// func (m *MyInstance) Progress(pState sdk.PluginState) (float64, string) {
//
// }

// Close is gets called by the SDK when the plugin source capture gets closed.
// This is useful to release any open resource used by each plugin instance.
// This method is optional for the event sourcing capability.
// func (m *MyInstance) Close() {
//
// }

// Destroy is gets called by the SDK when the plugin gets deinitialized.
// This is useful to release any open resource used by the plugin.
// This method is optional.
// func (m *MyPlugin) Destroy() {
//
// }

func main() {}
