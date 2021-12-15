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

// This plugin is a simple example of capture plugin.
// The plugin simply streams scap data by reading it from a file.
package main

import (
	"log"
	"os"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/capture"
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

// Defining a type for the plugin capture capture instances returned by Open().
//
// Composing the struct with plugins.BaseInstance is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in each plugin instance must be defined here.
// In this example, we store the internal os.File used to read scap data.
type MyInstance struct {
	capture.BaseInstance
	CurFile *os.File
}

// The plugin must be registered to the SDK in the init() function.
// The capture.Register function initializes our plugin as an capture
// plugin. This requires our plugin to implement the capture.Plugin
// interface, so compilation will fail if the mandatory methods are not
// implemented.
func init() {
	capture.Register(&MyPlugin{})
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory for capture plugins.
func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		Name:               "capture-example",
		Description:        "A Capture Plugin Example",
		Contact:            "github.com/falcosecurity/plugin-sdk-go/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.3.0",
	}
}

// Init initializes this plugin with a given config string, which is unused
// in this example. This method is mandatory for capture plugins.
func (m *MyPlugin) Init(config string) error {
	return nil
}

// Open opens the stream and start the capture (e.g. stream of scap data),
// creating a new plugin instance. The state of each instance can
// be initialized here. This method is mandatory for capture plugins.
func (m *MyPlugin) Open(params string) (capture.Instance, error) {
	file, err := os.Open(params)
	if err != nil {
		return nil, err
	}

	return &MyInstance{
		CurFile: file,
	}, nil
}

func (m *MyInstance) Read(pState sdk.PluginState, p []byte) (n int, err error) {
	return m.CurFile.Read(p)
}

// Close is gets called by the SDK when the plugin capture gets closed.
// This is useful to release any open resource used by each plugin instance.
// This method is optional for capture plugins.
func (m *MyInstance) Close() {
	if err := m.CurFile.Close(); err != nil {
		log.Println("[capture-example] Close, Error=" + err.Error())
	}
}

// Destroy is gets called by the SDK when the plugin gets deinitialized.
// This is useful to release any open resource used by the plugin.
// This method is optional for capture plugins.
// func (m *MyPlugin) Destroy() {
//
// }

func main() {}
