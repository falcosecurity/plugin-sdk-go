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

// This plugin is a simple example of source plugin.
// The plugin produces events of the "example" data source containing
// a single uint64 representing the incrementing value of a counter,
// serialized using a encoding/gob encoder.
package main

import (
	"encoding/gob"
	"fmt"
	"io"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
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
	config string
}

// Defining a type for the plugin source capture instances returned by Open().
// Multiple instances of the same plugin can be opened for different capture
// sessions.
//
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
// The source.Register function initializes our plugin as an source
// plugin. This requires our plugin to implement the source.Plugin
// interface, so compilation will fail if the mandatory methods are not
// implemented.
func init() {
	source.Register(&MyPlugin{})
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory for source plugins.
func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "source-example",
		Description: "A Source Plugin Example",
		Contact:     "github.com/falcosecurity/plugin-sdk-go/",
		Version:     "0.1.0",
		EventSource: "example",
	}
}

// Init initializes this plugin with a given config string, which is unused
// in this example. This method is mandatory for source plugins.
func (m *MyPlugin) Init(config string) error {
	m.config = config
	return nil
}

// Open opens the plugin source and starts a new capture session (e.g. stream
// of events), creating a new plugin instance. The state of each instance can
// be initialized here. This method is mandatory for source plugins.
func (m *MyPlugin) Open(params string) (source.Instance, error) {
	return &MyInstance{
		counter: 0,
	}, nil
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
	// We ignore the batching feature here, and just produce one event per time
	evt := evts.Get(0)
	m.counter++
	encoder := gob.NewEncoder(evt.Writer())
	if err := encoder.Encode(m.counter); err != nil {
		return 0, err
	}
	evt.SetTimestamp(uint64(time.Now().UnixNano()))
	return 1, nil
}

// Progress returns a percentage indicator referring to the production progress
// of the event source of this plugin.
// This method is optional for source plugins.
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
