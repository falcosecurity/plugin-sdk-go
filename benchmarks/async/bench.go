/*
Copyright (C) 2022 The Falco Authors.

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

// This is not a real plugin. The goal of this is to implement few
// plugin_* API symbols by leveraging the SDK Go, so that we can use
// the to execute the benchmark. This code is compiled as a c-archive
// and linked into a C executable so that each symbol will be a C -> Go call,
// thus simulating what really happens in the plugin framework.
package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
)

type MockPlugin struct {
	plugins.BasePlugin
}

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &MockPlugin{}
		extractor.Register(p)
		return p
	})
}

func (m *MockPlugin) Info() *plugins.Info {
	return &plugins.Info{}
}

func (m *MockPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{}
}

// note: we enable/disable the async extraction optimization depending on the
// passed-in config
func (m *MockPlugin) Init(config string) error {
	extract.SetAsync(config == "async")
	return nil
}

// note: we do nothing here, we're just interested in measuring the cost of
// calling this function from C
func (m *MockPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	return nil
}

// not used but required to build this as a c-archive
func main() {}
