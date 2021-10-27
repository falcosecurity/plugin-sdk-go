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

type MyPlugin struct {
	plugins.BasePlugin
	config string
}

type MyInstance struct {
	source.BaseInstance
	counter uint64
}

func init() {
	source.Register(&MyPlugin{})
}

func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 999,
		Name:               "source-example",
		Description:        "A Source Plugin Example",
		Contact:            "github.com/falcosecurity/plugin-sdk-go/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.2.0",
		EventSource:        "example",
	}
}

func (m *MyPlugin) Init(config string) error {
	m.config = config
	return nil
}

func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	var value uint64
	encoder := gob.NewDecoder(in)
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("[source-example] counter: %d", value), nil
}

func (m *MyPlugin) Open(params string) (source.Instance, error) {
	return &MyInstance{
		counter: 0,
	}, nil
}

func (m *MyInstance) Next(pState sdk.PluginState, evt sdk.EventWriter) error {
	m.counter++
	encoder := gob.NewEncoder(evt.Writer())
	if err := encoder.Encode(m.counter); err != nil {
		return err
	}
	evt.SetTimestamp(uint64(time.Now().UnixNano()))
	return nil
}

// // (optional: requires import _ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/progress)"
// func (m *MyInstance) Progress(pState sdk.PluginState) (float64, string) {
//
// }

// // (optional)
// func (m *MyPluginInstance) Close() {
//
// }

func main() {}
