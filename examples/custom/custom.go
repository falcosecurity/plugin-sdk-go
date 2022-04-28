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

// This plugin is an advanced example of source plugin with the optional
// extraction capabilities. Unlike the other examples, this does not make use
// on the high-level constructs of the sdk/plugins package, but instead
// it directly uses the low-level sdk/symbols packages. This approach is
// more complex and generally discouraged, but it can be useful in case a
// plugin developer has the need of defining an exported C symbol of the
// framework manually.
//
// The plugin produces events of the "example" data source containing
// a simple "hello world" string. The plugin is capable of extracting the
// "example.hello" field from the "example" event source, which just retrieves
// the hello world string written in the event.
package main

/*
#include <stdint.h>
*/
import "C"

// Importing "C" is necessary to include CGO in the plugin and export C symbols.
import (
	"fmt"
	"io/ioutil"
	"time"
	"unsafe"

	// Each one of these imported package provide a SDK prebuilt implementation
	// of some exported C symbols needed by the framework. The _ notation near
	// some inputs is necessary to avoid Go linters to remove the package if
	// unused.
	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/fields"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/nextbatch"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/open"
	// _ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/evtstr"
)

// Defining a type for the plugin.
// Composing the struct with plugins.Base* is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK. Each Base struct implement some interface methods
// required by the prebuilt C symbols of the SDK. Each symbol package documents
// which interface it expects to be implemented. Generally, not implementing
// a required interface leads to a panic at runtime.
//
// State variables to store in the plugin must be defined here.
// In this simple example, we store the configuration string passed by the
// SDK during the plugin initialization.
type MyPlugin struct {
	plugins.BaseLastError
	plugins.BaseExtractRequests
	plugins.BaseStringer
}

// Defining a type for the plugin source capture instances returned by Open().
// Multiple instances of the same plugin can be opened at the same time for
// different capture sessions.
// Composing the struct with plugins.BaseInstance is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in each plugin instance must be defined here.
type MyInstance struct {
	plugins.BaseEvents
	plugins.BaseProgress
}

// The plugin information must be initialized in the SDK in the init()
// function.
func init() {
	// Set the general plugin information one by one, also including
	// its type (source or extractor).
	info.SetId(999)
	info.SetName("custom-example")
	info.SetDescription("A Plugin Example")
	info.SetContact("github.com/falcosecurity/plugin-sdk-go")
	info.SetVersion("0.1.0")
	info.SetRequiredAPIVersion("0.2.0")
	info.SetEventSource("example")

	// Define an initialization callback
	initialize.SetOnInit(OnInit)

	// Define a callback for opening the event source.
	open.SetOnOpen(OnOpen)

	// Setting the fields supported for extraction.
	fields.SetFields([]sdk.FieldEntry{
		{Type: "string", Name: "example.hello", Display: "Hello World", Desc: "An hello world string"},
	})
}

// OnInit is a function that is called by the prebuilt plugin_init C symbol
// to initialize the plugin and return a plugin state.
func OnInit(config string) (sdk.PluginState, error) {
	return &MyPlugin{}, nil
}

// OnOpen is a function that is called by the prebuilt plugin_open C symbol
// to open the plugin event source and return a plugin instance state.
func OnOpen(params string) (sdk.InstanceState, error) {
	return &MyInstance{}, nil
}

// We provide a custom implementation of the plugin_event_to_string C symbol
// required by the framework, not using the prebuilt one provided by the SDK.
// The prebuilt one could be used by adding the following to the import list:
// 	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/evtstr"
// This implementation mimics the one of the prebuilt symbol. The purpose of
// this example is to show how to define custom C symbols to make them fit
// with the other SDk prebuilt symbols system.
//
//export plugin_event_to_string
func plugin_event_to_string(pState C.uintptr_t, data *C.uint8_t, datalen uint32) *C.char {
	// The prebuilt SDK symbols store the plugin state as a handle of the
	// SDK cgo.Handle. As such, using it is required to be compliant with the
	// other imported prebuilt symbols.
	pHandle := cgo.Handle(pState)

	// Our plugin state has a reusable buffer for the event_to_string method
	buffer := pHandle.Value().(sdk.StringerBuffer).StringerBuffer()

	// We use ptr.BytesReadWriter to safely accessing C-allocated memory
	bytesReader, err := ptr.NewBytesReadWriter(unsafe.Pointer(data), int64(datalen), int64(datalen))
	if err != nil {
		buffer.Write(err.Error())
	} else {
		// Read the string written in the event data using io funtions
		bytes, err := ioutil.ReadAll(bytesReader)
		if err != nil {
			buffer.Write(err.Error())
		} else {
			// Set the string as return value by writing it in the
			// reusable buffer
			buffer.Write(string(bytes))
		}
	}

	// Extract a char* pointer from the reusable buffer and use it as
	// the return value.
	return (*C.char)(buffer.CharPtr())
}

// This method is optional for source plugins, and enables the extraction
// capabilities. This is required and called by the prebuilt
// plugin_extract_fields C symbol.
func (p *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	bytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	switch req.FieldID() {
	case 0:
		req.SetValue(string(bytes))
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}

	return nil
}

// NextBatch produces a batch of new events, and is called repeatedly by the
// framework. For the prebuilt plugin_next_batch symbol, it's mandatory to
// specify a NextBatch method. The batch has a maximum size that dependes on
// the size of the underlying reusable memory buffer.
// A batch can be smaller than the maximum size.
func (i *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	evt := evts.Get(0)
	writer := evt.Writer()
	if _, err := writer.Write([]byte("hello world")); err != nil {
		return 0, err
	}
	evt.SetTimestamp(uint64(time.Now().UnixNano()))
	return 1, nil
}

// Progress returns a percentage indicator referring to the production progress
// of the event source of this plugin.
// func (m *MyInstance) Progress(pState sdk.PluginState) (float64, string) {
//
// }

// Close is gets called by the prebuilt plugin_close C symbol when the plugin
// source capture gets closed. This is useful to release any open resource used
// by each plugin instance.
// func (p *MyInstance) Close() {
//
// }

// Destroy is gets called by the prebuilt plugin_destroy C symbol when the
// plugin gets deinitialized. This is useful to release any open resource
// used by the plugin.
// func (p *MyPlugin) Destroy() {
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
