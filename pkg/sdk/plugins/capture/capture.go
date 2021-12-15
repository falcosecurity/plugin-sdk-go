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

// Package capture provides high-level constructs to easily build
// capture plugins.
package capture

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/open"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/read"
)

var registered = false

// Plugin is an interface representing a capture plugin.
type Plugin interface {
	plugins.Plugin
	//
	// Open opens the stream and start the capture (e.g. stream of scap data)
	//
	// The argument string represents the user-defined parameters and
	// can be used to customize how the capture is opened.
	// The return value is an Instance representing the capture session.
	// A successfull call to Open returns a nil error.
	Open(params string) (Instance, error)
}

// Instance is an interface representing a capture session instance
// returned by a call to Open of a capture plugin.
//
// Implementations of this interface must implement io.Reader, and can
// optionally implement sdk.Closer.
// If sdk.Closer is implemented, the Close method will be called while closing
// the capture session.
type Instance interface {
	// (optional) sdk.Closer
	sdk.Reader
}

// BaseInstance is a base implementation of the Instance interface.
// Developer-defined Instance implementations should be composed with BaseInstance
// to have out-of-the-box compliance with all the required interfaces.
type BaseInstance struct {
}

// Register registers a Plugin capture plugin in the framework. This function
// needs to be called in a Go init() function. Calling this function more than
// once will cause a panic.
func Register(p Plugin) {
	if registered {
		panic("plugin-sdk-go/sdk/plugins/capture: register can be called only once")
	}

	i := p.Info()
	info.SetType(sdk.TypeCapturePlugin)
	info.SetName(i.Name)
	info.SetDescription(i.Description)
	info.SetContact(i.Contact)
	info.SetVersion(i.Version)
	info.SetRequiredAPIVersion(i.RequiredAPIVersion)

	initialize.SetOnInit(func(c string) (sdk.PluginState, error) {
		err := p.Init(c)
		return p, err
	})

	open.SetOnOpen(func(c string) (sdk.InstanceState, error) {
		return p.Open(c)
	})

	registered = true
}
