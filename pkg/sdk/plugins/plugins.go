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

package plugins

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

type Info struct {
	ID                  uint32
	Name                string
	Description         string
	EventSource         string
	Contact             string
	Version             string
	RequiredAPIVersion  string
	ExtractEventSources []string
}

type Plugin interface {
	sdk.LastError
	sdk.LastErrorBuffer
	Info() *Info
	Init(config string) error
	// (optional): sdk.Destroyer
}

type BaseEvents struct {
	events sdk.EventWriters
}

func (b *BaseEvents) Events() sdk.EventWriters {
	return b.events
}

func (b *BaseEvents) SetEvents(events sdk.EventWriters) {
	b.events = events
}

type BaseExtractRequests struct {
	extrReqPool sdk.ExtractRequestPool
}

func (b *BaseExtractRequests) ExtractRequests() sdk.ExtractRequestPool {
	return b.extrReqPool
}

func (b *BaseExtractRequests) SetExtractRequests(pool sdk.ExtractRequestPool) {
	b.extrReqPool = pool
}

type BaseLastError struct {
	lastErr    error
	lastErrBuf ptr.StringBuffer
}

func (b *BaseLastError) LastError() error {
	return b.lastErr
}

func (b *BaseLastError) SetLastError(err error) {
	b.lastErr = err
}

func (b *BaseLastError) LastErrorBuffer() sdk.StringBuffer {
	return &b.lastErrBuf
}

type BaseStringer struct {
	stringerBuf ptr.StringBuffer
}

func (b *BaseStringer) StringerBuffer() sdk.StringBuffer {
	return &b.stringerBuf
}

type BaseProgress struct {
	progressBuf ptr.StringBuffer
}

func (b *BaseProgress) ProgressBuffer() sdk.StringBuffer {
	return &b.progressBuf
}

type BasePlugin struct {
	BaseLastError
	BaseStringer
	BaseProgress
	BaseExtractRequests
}
