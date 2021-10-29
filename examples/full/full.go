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

// This plugin is a simple example of source plugin with the optional
// extraction capabilities.
// The plugin produces events of the "example" data source containing
// a single uint64 representing the incrementing value of a counter,
// serialized using a encoding/gob encoder. The plugin is capable of
// extracting the "example.count" and "example.countstr" fields from the
// "example" event source, which are simple numeric and string representations
// of the counter value.
package main

import (
	"encoding/gob"
	"fmt"
	"io"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// Defining a type for the plugin.
// Composing the struct with plugins.BasePlugin is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in the plugin must be defined here.
// In this simple example, we store the configuration string passed by the
// SDK during the plugin initialization.
type MyPlugin struct {
	plugins.BasePlugin
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
// declares to the SDK a source plugin with the optional extraction features
// enabled. The order in which the two Register functions are called is not
// relevant, as the SDK induces that the registered plugin is a source plugin.
// This requires our plugin to implement the source.Plugin interface, so
// compilation will fail if the mandatory methods are not implemented.
func init() {
	p := &MyPlugin{}
	extractor.Register(p)
	source.Register(p)
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory for source plugins.
func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 999,
		Name:               "full-example",
		Description:        "A Plugin Example for both Source and Extraction",
		Contact:            "github.com/falcosecurity/plugin-sdk-go/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.2.0",
		EventSource:        "example",
	}
}

// Init initializes this plugin with a given config string, which is unused
// in this example. This method is mandatory for source plugins.
func (m *MyPlugin) Init(config string) error {
	return nil
}

// Fields return the list of extractor fields exported by this plugin.
// This method is optional for source plugins, and enables the extraction
// capabilities. If the Fields method is defined, the framework expects
// an Extract method to be specified too.
func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "example.count", Display: "Counter value", Desc: "Current value of the internal counter"},
		{Type: "string", Name: "example.countstr", Display: "Counter string value", Desc: "String represetation of current value of the internal counter"},
	}
}

// This method is optional for source plugins, and enables the extraction
// capabilities. If the Extract method is defined, the framework expects
// an Fields method to be specified too.
func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var value uint64
	encoder := gob.NewDecoder(evt.Reader())
	if err := encoder.Decode(&value); err != nil {
		return err
	}

	switch req.FieldID() {
	case 0:
		req.SetU64Value(value)
		return nil
	case 1:
		req.SetStrValue(fmt.Sprintf("%d", value))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

// Open opens the plugin source and starts a new capture session (e.g. stream
// of events), creating a new plugin instance. The state of each instance can
// be initialized here. This method is mandatory for source plugins.
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
		counter: 0,
	}
	myInstance.SetEvents(myBatch)
	return myInstance, nil
}

// String produces a string representation of an event data produced by the
// event source of this plugin. This method is mandatory for source plugins.
func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	var value uint64
	encoder := gob.NewDecoder(in)
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("counter: %d", value), nil
}

// NextBatch produces a batch of new events, and is called repeatedly by the
// framework. For source plugins, it's mandatory to specify a NextBatch method.
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
// This method is optional for source plugins. If specified, the following
// package needs to be imported to advise the SDK to enable this feature:
// import _ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/progress"
// func (m *MyInstance) Progress(pState sdk.PluginState) (float64, string) {
//
// }

// Close is gets called by the SDK when the plugin source capture gets closed.
// This is useful to release any open resource used by each plugin instance.
// This method is optional for source plugins.
// func (m *MyInstance) Close() {
//
// }

// Destroy is gets called by the SDK when the plugin gets deinitialized.
// This is useful to release any open resource used by the plugin.
// This method is optional for source plugins.
// func (m *MyPlugin) Destroy() {
//
// }

func main() {}
