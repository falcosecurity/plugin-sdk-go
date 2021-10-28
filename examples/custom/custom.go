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
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/evtstr"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/fields"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/nextbatch"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/open"
)

type MyPlugin struct {
	plugins.BaseLastError
	plugins.BaseExtractRequests
	plugins.BaseStringer
}

type MyInstance struct {
	plugins.BaseEvents
	plugins.BaseProgress
}

func init() {
	info.SetId(999)
	info.SetName("custom-example")
	info.SetDescription("A Source Plugin Example")
	info.SetContact("github.com/falcosecurity/plugin-sdk-go")
	info.SetVersion("0.1.0")
	info.SetRequiredAPIVersion("0.2.0")
	info.SetType(sdk.TypeSourcePlugin)
	info.SetEventSource("example")

	initialize.SetOnInit(OnInit)
	open.SetOnOpen(OnOpen)

	fields.SetFields([]sdk.FieldEntry{
		{Type: "string", Name: "example.hello", Display: "Hello World", Desc: "An hello world string"},
	})
}

func OnInit(config string) (sdk.PluginState, error) {
	return &MyPlugin{}, nil
}

func OnOpen(params string) (sdk.InstanceState, error) {
	return &MyInstance{}, nil
}

func (i *MyPlugin) String(in io.ReadSeeker) (string, error) {
	b, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (i *MyInstance) Next(pState sdk.PluginState, evt sdk.EventWriter) error {
	writer := evt.Writer()
	if _, err := writer.Write([]byte("hello world")); err != nil {
		return err
	}
	evt.SetTimestamp(uint64(time.Now().UnixNano()))
	return nil
}

func (p *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	bytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	switch req.FieldID() {
	case 0:
		req.SetStrValue(string(bytes))
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}

	return nil
}

// // (optional)
// func (i *instanceState) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) error {
//
// }

// // (optional)
// func (p *instanceState) Close() {
//
// }

// // (optional)
// func (p *MyPlugin) Destroy() {
//
// }

func main() {}
