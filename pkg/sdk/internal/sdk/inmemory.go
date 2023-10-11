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

package sdk

import (
	"bytes"
	"io"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// InMemoryExtractRequest is an in-memory implementation of
// sdk.ExtractRequest that allows changing its internal values.
type InMemoryExtractRequest struct {
	ValFieldID    uint64
	ValFieldType  uint32
	ValField      string
	ValArgKey     string
	ValArgIndex   uint64
	ValArgPresent bool
	ValIsList     bool
	ValValue      interface{}
	ValPtr        unsafe.Pointer
}

func (i *InMemoryExtractRequest) FieldID() uint64 {
	return i.ValFieldID
}

func (i *InMemoryExtractRequest) FieldType() uint32 {
	return i.ValFieldType
}

func (i *InMemoryExtractRequest) Field() string {
	return i.ValField
}

func (i *InMemoryExtractRequest) ArgKey() string {
	return i.ValArgKey
}

func (i *InMemoryExtractRequest) ArgIndex() uint64 {
	return i.ValArgIndex
}

func (i *InMemoryExtractRequest) ArgPresent() bool {
	return i.ValArgPresent
}

func (i *InMemoryExtractRequest) IsList() bool {
	return i.ValIsList
}

func (i *InMemoryExtractRequest) SetValue(v interface{}) {
	i.ValValue = v
}

func (i *InMemoryExtractRequest) SetPtr(ptr unsafe.Pointer) {
	i.ValPtr = ptr
}

// InMemoryExtractRequestPool is an in-memory implementation of
// sdk.ExtractRequestPool that allows changing its internal values.
type InMemoryExtractRequestPool struct {
	Requests map[int]sdk.ExtractRequest
}

func (i *InMemoryExtractRequestPool) Get(requestIndex int) sdk.ExtractRequest {
	return i.Requests[requestIndex]
}

func (i *InMemoryExtractRequest) Free() {
	// do nothing
}

// InMemoryEventWriter is an in-memory implementation of
// sdk.EventWriter that allows changing its internal values.
type InMemoryEventWriter struct {
	Buffer       bytes.Buffer
	ValTimestamp uint64
}

func (i *InMemoryEventWriter) Writer() io.Writer {
	i.Buffer.Reset()
	return &i.Buffer
}

func (i *InMemoryEventWriter) SetTimestamp(value uint64) {
	i.ValTimestamp = value
}

// InMemoryEventWriters is an in-memory implementation of
// sdk.EventWriters that allows changing its internal values.
type InMemoryEventWriters struct {
	Writers     []sdk.EventWriter
	ValArrayPtr unsafe.Pointer
	OnFree      func()
}

func (i *InMemoryEventWriters) Get(eventIndex int) sdk.EventWriter {
	return i.Writers[eventIndex]
}

func (i *InMemoryEventWriters) Len() int {
	return len(i.Writers)
}

func (i *InMemoryEventWriters) ArrayPtr() unsafe.Pointer {
	return i.ValArrayPtr
}

func (i *InMemoryEventWriters) Free() {
	if i.OnFree != nil {
		i.OnFree()
	}
}

// InMemoryEventReader is an in-memory implementation of
// sdk.EventReader that allows changing its internal values.
type InMemoryEventReader struct {
	Buffer       []byte
	ValEventNum  uint64
	ValTimestamp uint64
}

func (i *InMemoryEventReader) EventNum() uint64 {
	return i.ValEventNum
}

func (i *InMemoryEventReader) Timestamp() uint64 {
	return i.ValTimestamp
}

func (i *InMemoryEventReader) Reader() io.ReadSeeker {
	return bytes.NewReader(i.Buffer)
}
