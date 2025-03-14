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

/*
#include <stdlib.h>
#include "plugin_types.h"
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

// pluginEventCode is the event code for the PPME_PLUGINEVENT_E scap event.
// todo(jasondellaluce): pull this information from falcosecurity/libs in the future
const pluginEventCode = 322

// PluginEventHeaderSize is the size of a scap event header, plus the
// params lenght and the plugin ID integers of a PPME_PLUGINEVENT_E event.
// In other words, this is the size of a plugin event with an empty data payload.
const PluginEventHeaderSize = C.sizeof_ss_plugin_event + 4 + 4 + 4

// EventWriter can be used to represent events produced by a plugin.
// This interface is meant to be used in the next/next_batch.
//
// Data inside an event can only be accessed in write-only mode
// through the io.Writer interface returned by the Writer method.
//
// Instances of this interface should be retrieved through the Get
// method of sdk.EventWriters.
type EventWriter interface {
	// Writer returns an instance of io.Writer that points to the
	// event data. This is the only way to write inside the event data.
	//
	// Each invocation of Writer clears the event data and sets its
	// size to zero. As such, consequent invocations of Writer can
	// potentially return two distinct instances of io.Writer, and
	// any data written inside the event would be erased.
	Writer() io.Writer
	//
	// SetTimestamp sets the timestamp of the event.
	SetTimestamp(value uint64)
}

// EventReader can be used to represent events passed by the framework
// to the plugin. This interface is meant to be used during extraction.
//
// Data inside an event can only be accessed in read-only mode
// through the io.Reader interface returned by the Reader method.
type EventReader interface {
	// EventNum returns the number assigned to the event by the framework.
	EventNum() uint64
	//
	// Timestamp returns the timestamp of the event.
	Timestamp() uint64
	//
	// Reader returns an instance of io.ReadSeeker that points to the
	// event data. This is the only way to read from the event data.
	//
	// This method returns an instance of io.ReadSeeker to leave the door
	// open for seek-related optimizations, which could be useful in the
	// field extraction use case.
	Reader() io.ReadSeeker
}

// EventWriters represent a list of sdk.EventWriter to be used inside
// plugins. This interface hides the complexities related to the internal
// representation of C strutures and to the optimized memory management.
// Internally, this wraps an array of ss_plugin_event C structs that are
// compliant with the symbols and APIs of the plugin framework.
// The underlying C array can be accessed through the ArrayPtr method as
// an unsafe.Pointer. Manually writing inside the C array might break the
// internal logic of sdk.EventWriters and lead to undefined behavior.
//
// This is intended to be used as a slab memory allocator. EventWriters
// are supposed to be stored inside the plugin instance state to avoid
// useless reallocations, and should be used to create plugin events and
// write their data. Unlike slices, the events contained in the list
// can only be accessed by using the Get and Len methods to enforce safe
// memory accesses. Ideally, the list is meant to be large enough to contain
// the maximum number of events that the plugin is capable of producing with
// plugin_next_batch.
type EventWriters interface {
	// Get returns an instance of sdk.EventWriter at the eventIndex
	// position inside the list.
	Get(eventIndex int) EventWriter
	//
	// Len returns the size of the list, namely the number of events
	// it contains. Using Len coupled with Get allows iterating over
	// all the events of the list.
	Len() int
	//
	// ArrayPtr return an unsafe pointer to the underlying C array of
	// ss_plugin_event. The returned pointer should only be used for
	// read tasks or for being passed to the plugin framework.
	// Writing in the memory pointed by this pointer is unsafe and might
	// lead to non-deterministic behavior.
	ArrayPtr() unsafe.Pointer
	//
	// Free deallocates any memory used by the list that can't be disposed
	// through garbage collection. The behavior of Free after the first call
	// is undefined.
	Free()
}

type eventWriters struct {
	evts    []*eventWriter
	evtPtrs **C.ss_plugin_event
}

// NewEventWriters creates a new instance of sdk.EventWriters.
// The size argument indicates the length of the list, which is the amount
// of events contained. Then dataSize argument indicates the maximum data
// size of each event.
func NewEventWriters(size, dataSize int64) (EventWriters, error) {
	if size < 1 {
		return nil, fmt.Errorf("invalid size: %d", size)
	}
	if dataSize < 0 || dataSize > C.UINT32_MAX {
		return nil, fmt.Errorf("invalid dataSize: %d", dataSize)
	}

	ret := &eventWriters{
		evts:    make([]*eventWriter, size),
		evtPtrs: (**C.ss_plugin_event)(C.malloc((C.size_t)(size * C.sizeof_uintptr_t))),
	}

	var err error
	for i := range ret.evts {
		if ret.evts[i], err = newEventWriter(dataSize); err != nil {
			return nil, err
		}
		*(**C.ss_plugin_event)(unsafe.Pointer(uintptr(unsafe.Pointer(ret.evtPtrs)) + uintptr(i*C.sizeof_uintptr_t))) = ret.evts[i].ssPluginEvt
	}
	return ret, nil
}

func (p *eventWriters) Get(eventIndex int) EventWriter {
	return p.evts[eventIndex]
}

func (p *eventWriters) Len() int {
	return len(p.evts)
}

func (p *eventWriters) Free() {
	for _, pe := range p.evts {
		pe.free()
	}
	C.free( /*(*C.ss_plugin_event)*/ p.ArrayPtr())
}

func (p *eventWriters) ArrayPtr() unsafe.Pointer {
	return unsafe.Pointer(p.evtPtrs)
}

type eventWriter struct {
	data        ptr.BytesReadWriter
	dataSize    int64
	ssPluginEvt *C.ss_plugin_event
}

func newEventWriter(dataSize int64) (*eventWriter, error) {
	evt := (*C.ss_plugin_event)(C.calloc(1, C.size_t(dataSize+PluginEventHeaderSize)))
	evt._type = pluginEventCode
	evt.ts = C.uint64_t(C.UINT64_MAX)
	evt.tid = C.uint64_t(C.UINT64_MAX)
	evt.len = (C.uint32_t)(PluginEventHeaderSize)
	// note(jasondellaluce): CGO fails to properly encode nparams for *reasons*,
	// so we're forced to write their value manually with an offset
	*(*C.uint32_t)(unsafe.Pointer(uintptr(unsafe.Pointer(evt)) + 22)) = 2
	// plugin ID size (4 bytes)
	*(*C.uint32_t)(unsafe.Pointer(uintptr(unsafe.Pointer(evt)) + C.sizeof_ss_plugin_event + 0)) = 4
	// data payload size (0 bytes for now)
	*(*C.uint32_t)(unsafe.Pointer(uintptr(unsafe.Pointer(evt)) + C.sizeof_ss_plugin_event + 4)) = 0
	// plugin ID value (note: putting zero makes the framework set it automatically)
	*(*C.uint32_t)(unsafe.Pointer(uintptr(unsafe.Pointer(evt)) + C.sizeof_ss_plugin_event + 8)) = 0
	// create a read/writer for the data payload
	brw, err := ptr.NewBytesReadWriter(unsafe.Pointer(uintptr(unsafe.Pointer(evt))+PluginEventHeaderSize), int64(dataSize), int64(dataSize))
	if err != nil {
		return nil, err
	}

	return &eventWriter{
		ssPluginEvt: evt,
		data:        brw,
		dataSize:    dataSize,
	}, nil
}

func (p *eventWriter) dataLenPtr() *C.uint32_t {
	return (*C.uint32_t)(unsafe.Pointer(uintptr(unsafe.Pointer(p.ssPluginEvt)) + C.sizeof_ss_plugin_event + 4))
}

func (p *eventWriter) Writer() io.Writer {
	p.data.SetLen(p.dataSize)
	p.data.Seek(0, io.SeekStart)
	p.ssPluginEvt.len = (C.uint32_t)(PluginEventHeaderSize)
	*p.dataLenPtr() = 0
	return p
}

func (p *eventWriter) Write(data []byte) (n int, err error) {
	n, err = p.data.Write(data)
	if err != nil {
		return
	}
	p.ssPluginEvt.len += C.uint32_t(n)
	*p.dataLenPtr() += C.uint32_t(n)
	return
}

func (p *eventWriter) SetTimestamp(value uint64) {
	(*C.ss_plugin_event)(p.ssPluginEvt).ts = C.uint64_t(value)
}

func (p *eventWriter) free() {
	C.free(unsafe.Pointer(p.ssPluginEvt))
	p.data = nil
}

type eventReader C.ss_plugin_event_input

// NewEventReader wraps a pointer to a ss_plugin_event_input C structure to create
// a new instance of EventReader. It's not possible to check that the pointer is valid.
// Passing an invalid pointer may cause undefined behavior.
func NewEventReader(ssPluginEvtInput unsafe.Pointer) EventReader {
	return (*eventReader)(ssPluginEvtInput)
}

func (e *eventReader) Reader() io.ReadSeeker {
	if e.evt._type != pluginEventCode {
		panic(fmt.Sprintf("plugin-sdk-go/sdk: reveived extraction request for non-plugin event (code=%d)", e.evt._type))
	}
	datalen := *(*C.uint32_t)(unsafe.Pointer(uintptr(unsafe.Pointer(e.evt)) + C.sizeof_ss_plugin_event + 4))
	brw, _ := ptr.NewBytesReadWriter(unsafe.Pointer(uintptr(unsafe.Pointer(e.evt))+PluginEventHeaderSize), int64(datalen), int64(datalen))
	return brw
}

func (e *eventReader) Timestamp() uint64 {
	return uint64(e.evt.ts)
}

func (e *eventReader) EventNum() uint64 {
	return uint64(e.evtnum)
}
