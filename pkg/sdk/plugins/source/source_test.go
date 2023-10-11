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

package source

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
)

type testPlugin struct {
	plugins.BasePlugin
}

type testInstance struct {
	BaseInstance
}

func (m *testPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 999,
		Name:               "test",
		Description:        "Source Test",
		Contact:            "",
		Version:            "",
		RequiredAPIVersion: "",
		EventSource:        "test",
	}
}

func (m *testPlugin) Init(config string) error {
	return nil
}

func (m *testPlugin) Open(params string) (Instance, error) {
	return &testInstance{}, nil
}

func (m *testPlugin) String(evt sdk.EventReader) (string, error) {
	return "", nil
}

func (m *testInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	return 0, nil
}
