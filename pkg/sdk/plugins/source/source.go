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

package source

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/evtstr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/info"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/initialize"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/lasterr"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/nextbatch"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/open"
)

var registered = false

type Plugin interface {
	plugins.Plugin
	sdk.Stringer
	Open(params string) (Instance, error)
}

type Instance interface {
	sdk.Events
	sdk.Nexter
	// (optional) sdk.Closer
	// (optional) sdk.NextBatcher
	// (optional) sdk.Progresser
}

type BaseInstance struct {
	plugins.BaseEvents
}

func Register(p Plugin) {
	if registered {
		panic("plugin-sdk-go/sdk/plugins/source: register can be called only once")
	}

	i := p.Info()
	info.SetType(sdk.TypeSourcePlugin)
	info.SetId(i.ID)
	info.SetName(i.Name)
	info.SetDescription(i.Description)
	info.SetEventSource(i.EventSource)
	info.SetContact(i.Contact)
	info.SetVersion(i.Version)
	info.SetRequiredAPIVersion(i.RequiredAPIVersion)
	info.SetExtractEventSources(i.ExtractEventSources)

	initialize.SetOnInit(func(c string) (sdk.PluginState, error) {
		err := p.Init(c)
		return p, err
	})

	open.SetOnOpen(func(c string) (sdk.InstanceState, error) {
		return p.Open(c)
	})

	registered = true
}
