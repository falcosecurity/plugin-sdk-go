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

// This plugin is a simple example of plugin with event sourcing capability.
// The plugin produces events of the "example" data source containing
// a single uint64 representing the incrementing value of a counter,
// serialized using a encoding/gob encoder.
// This plugin makes use of the SDK-provided "pull" source instance to
// open the event source, so we'll not provide a type implementation of
// the source.Instance interface here
package main

import (
	"context"
	"encoding/gob"
	"fmt"
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

// The plugin must be registered to the SDK in the init() function.
// The source.Register function initializes our plugin as an source
// plugin. This requires our plugin to implement the source.Plugin
// interface, so compilation will fail if the mandatory methods are not
// implemented.
func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &MyPlugin{}
		source.Register(p)
		return p
	})
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory.
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
// in this example. This method is mandatory.
func (m *MyPlugin) Init(config string) error {
	m.config = config
	return nil
}

// Open opens the plugin source and starts a new capture session (e.g. stream
// of events). This uses the SDK built-in source.NewPullInstance() function
// that allows creating an event source by simply providing a event-generating
// callback. This method is mandatory for the event sourcing capability.
func (m *MyPlugin) Open(params string) (source.Instance, error) {
	counter := uint64(0)
	pull := func(ctx context.Context, evt sdk.EventWriter) error {
		counter++
		if err := gob.NewEncoder(evt.Writer()).Encode(counter); err != nil {
			return err
		}
		evt.SetTimestamp(uint64(time.Now().UnixNano()))
		return nil
	}
	return source.NewPullInstance(pull)
}

// String produces a string representation of an event data produced by the
// event source of this plugin.
// This method is optional for the event sourcing capability.
func (m *MyPlugin) String(evt sdk.EventReader) (string, error) {
	var value uint64
	encoder := gob.NewDecoder(evt.Reader())
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("counter: %d", value), nil
}

// Destroy is gets called by the SDK when the plugin gets deinitialized.
// This is useful to release any open resource used by the plugin.
// This method is optional.
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
// This method is optional.
// func (m *MyPlugin) InitSchema() *sdk.SchemaInfo {
//
// }

func main() {}
