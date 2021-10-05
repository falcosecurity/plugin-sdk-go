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

package sdk

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct ss_plugin_event
{
	uint64_t evtnum;
	uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;


*/
import "C"
import (
	"fmt"
	"io"
	"math"
	"unsafe"
)

// Functions that return or update a rc (e.g. plugin_init,
// plugin_open) should return one of these values.
const (
	SSPluginSuccess         int32 = 0
	SSPluginFailure         int32 = 1
	SSPluginTimeout         int32 = -1
	SSPluginIllegalInput    int32 = 3
	SSPluginNotFound        int32 = 4
	SSPluginInputTooSmall   int32 = 5
	SSPluginEOF             int32 = 6
	SSPluginUnexpectedBlock int32 = 7
	SSPluginVersionMismatch int32 = 8
	SSPluginNotSupported    int32 = 9
)

// One of these values should be returned by plugin_get_type().
const (
	TypeSourcePlugin    uint32 = 1
	TypeExtractorPlugin uint32 = 2
)

// The data payload allocated and returned in a call to
// plugin_next/plugin_next_batch() should not be larger than this.
const MaxEvtSize uint32 = 65635

// The maximum number of events to return from a call to
// plugin_next_batch when using the wrapper function NextBatch().
const MaxNextBatchEvents = 512

// The full set of values that someday might be returned in the ftype
// member of ss_plugin_extract_field structs. For now, only
// ParamTypeUint64/ParamTypeCharBuf are used.
const (
	ParamTypeNone             uint32 = 0
	ParamTypeInt8             uint32 = 1
	ParamTypeInt16            uint32 = 2
	ParamTypeInt32            uint32 = 3
	ParamTypeInt64            uint32 = 4
	ParamTypeUintT8           uint32 = 5
	ParamTypeUint16           uint32 = 6
	ParamTypeUint32           uint32 = 7
	ParamTypeUint64           uint32 = 8
	ParamTypeCharBuf          uint32 = 9  // A printable buffer of bytes, NULL terminated
	ParamTypeByteBuf          uint32 = 10 // A raw buffer of bytes not suitable for printing
	ParamTypeErrno            uint32 = 11 // this is an INT64, but will be interpreted as an error code
	ParamTypeSockaddr         uint32 = 12 // A sockaddr structure, 1byte family + data
	ParamTypeSocktuple        uint32 = 13 // A sockaddr tuple,1byte family + 12byte data + 12byte data
	ParamTypeFd               uint32 = 14 // An fd, 64bit
	ParamTypePid              uint32 = 15 // A pid/tid, 64bit
	ParamTypeFdlist           uint32 = 16 // A list of fds, 16bit count + count * (64bit fd + 16bit flags)
	ParamTypeFspath           uint32 = 17 // A string containing a relative or absolute file system path, null terminated
	ParamTypeSyscallId        uint32 = 18 // A 16bit system call ID. Can be used as a key for the g_syscall_info_table table.
	ParamTypeSigYype          uint32 = 19 // An 8bit signal number
	ParamTypeRelTime          uint32 = 20 // A relative time. Seconds * 10^9  + nanoseconds. 64bit.
	ParamTypeAbsTime          uint32 = 21 // An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit.
	ParamTypePort             uint32 = 22 // A TCP/UDP prt. 2 bytes.
	ParamTypeL4Proto          uint32 = 23 // A 1 byte IP protocol type.
	ParamTypeSockfamily       uint32 = 24 // A 1 byte socket family.
	ParamTypeBool             uint32 = 25 // A boolean value, 4 bytes.
	ParamTypeIpv4Addr         uint32 = 26 // A 4 byte raw IPv4 address.
	ParamTypeDyn              uint32 = 27 // Type can vary depending on the context. Used for filter fields like evt.rawarg.
	ParamTypeFlags8           uint32 = 28 // this is an UINT8, but will be interpreted as 8 bit flags.
	ParamTypeFlags16          uint32 = 29 // this is an UINT16, but will be interpreted as 16 bit flags.
	ParamTypeFlags32          uint32 = 30 // this is an UINT32, but will be interpreted as 32 bit flags.
	ParamTypeUid              uint32 = 31 // this is an UINT32, MAX_UINT32 will be interpreted as no value.
	ParamTypeGid              uint32 = 32 // this is an UINT32, MAX_UINT32 will be interpreted as no value.
	ParamTypeDouble           uint32 = 33 // this is a double precision floating point number.
	ParamTypeSigSet           uint32 = 34 // sigset_t. I only store the lower UINT32 of it
	ParamTypeCharBufArray     uint32 = 35 // Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only.
	ParamTypeCharBufPairArray uint32 = 36 // Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only.
	ParamTypeIpv4Net          uint32 = 37 // An IPv4 network.
	ParamTypeIpv6Addr         uint32 = 38 // A 16 byte raw IPv6 address.
	ParamTypeIpv6Net          uint32 = 39 // An IPv6 network.
	ParamTypeIpAddr           uint32 = 40 // Either an IPv4 or IPv6 address. The length indicates which one it is.
	ParamTypeIpNet            uint32 = 41 // Either an IPv4 or IPv6 network. The length indicates which one it is.
	ParamTypeMode             uint32 = 42 // a 32 bit bitmask to represent file modes.
	ParamTypeFsRelPath        uint32 = 43 // A path relative to a dirfd.
	ParamTypeMax              uint32 = 44 // array size
)

// FieldEntry represents a single field entry that an extractor plugin can expose.
// Should be used when implementing plugin_get_fields().
type FieldEntry struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	ArgRequired bool   `json:"argRequired"`
	Display     string `json:"display"`
	Desc        string `json:"desc"`
	Properties  string `json:"properties"`
}

// PluginEvent can be used to represent events produced by a plugin.
// This interface is meant to be used in the next/next_batch and
// the extraction flows.
//
// Data inside an event can only be accessed
// either in read-only or write-only mode through the Reader and
// Writer methods respectively.
//
// Instances of this interface should be retrieved through the Get
// method of sdk.PluginEvents.
type PluginEvent interface {
	// Writer returns an instance of io.Writer that points to the
	// event data. This is the only way to write inside the event data.
	//
	// Each invocation of Writer clears the event data and sets its
	// size to zero. As such, consequent invocations of Writer can
	// potentially return two distinct instances of io.Writer, and
	// that any data written inside the event will be erased.
	Writer() io.Writer
	//
	// Reader returns an instance of io.ReadSeeker that points to the
	// event data. This is the only way to read from the event data.
	// If no data has yet be written through the Writer method, the
	// reader will read no data. Only data written through the Writer
	// method will be readable.
	//
	// This method returns an instance of io.ReadSeeker to leave the door
	// open for seek-related optimizations, which could be useful in the
	// field extraction use case.
	Reader() io.ReadSeeker
	//
	// SetTimestamp sets the timestamp of the event. This is supposed
	// to be invoked in the next/next_batch flow.
	SetTimestamp(value uint64) // todo(jasondellaluce, leogr): set default value to current timestamp?
}

// PluginEvents represent a list of sdk.PluginEvent to be used inside
// plugins. This interface hides the complexities related to the internal
// representation of C strutures and to the optimized memory management.
// Internally, this wraps an array of ss_plugin_event C structs that are
// compliant with the symbols and APIs of the plugin framework.
// The underlying C array can be accessed through the ArrayPtr method as
// an unsafe.Pointer. Manually writing inside the C array might break the
// internal logic of sdk.PluginEvents thus leading to non-deterministic
// behavior.
//
// This is intended to be used as a slab memory allocator. PluginEvents
// are supposed to be stored inside the plugin instance state to avoid
// useless reallocations, and should be used to create plugin events and
// write data in them. Unlike slices, the events contained in the list
// can only be accessed by using the Get and Len methods to enforce safe
// memory accesses. Ideally, the list is meant to be large enough to contain
// the maximum number of events that the plugin is capable of producing with
// plugin_next_batch. The plugin_next symbol should only work on the first
// event of the list instead.
//
// The underlying C memory managed by this interface is out of the scope of
// garbage collection, and memory must be manually deallocated by invoking
// the Free method. Using instances of PluginEvents after invoking its Free()
// method might lead to non-deterministic behavior.
//
// Here is an example of usage:
//	func plugin_open(pState unsafe.Pointer, params *C.char, rc *int32) unsafe.Pointer {
//		...
//		// Create instance of sdk.PluginEvents
//		pluginEvents, err := sdk.NewPluginEvents(maxNextBatchEvents, int64(sdk.MaxEvtSize))
//		if err != nil {
//			*rc = sdk.SSPluginFailure
//			return nil
//		}
//
//		// Store pluginEvents inside the plugin instance state
//		is := &instanceState{
//			...
//			pluginEvents:       pluginEvents,
//		}
//		handle := state.NewStateContainer()
//		state.SetContext(handle, unsafe.Pointer(is))
//		*rc = sdk.SSPluginSuccess
//		return handle
//	}
//
//	func plugin_next(pState unsafe.Pointer, iState unsafe.Pointer, retEvt **C.ss_plugin_event) int32 {
//		// Grab an instance of the event through sdk.PluginEvents
//		is := (*instanceState)(state.Context(iState))
//		event := is.pluginEvents.Get(0)
//
//		// Write the event data and set the timestamp
//		eventData := "Sample event data... Hello World!"
//		eventWriter := event.Writer()
//		eventWriter.Write([]byte(eventData))
//		event.SetTimestamp(uint64(time.Now().Unix()) * 1000000000)
//
//		// Set the result pointer to the internal event array buffer
//		*retEvt = (*C.ss_plugin_event)(is.pluginEvents.ArrayPtr())
//		return sdk.SSPluginSuccess
//	}
//
type PluginEvents interface {
	// Get returns an instance of sdk.PluginEvent at the eventIndex
	// position inside the list.
	Get(eventIndex int) PluginEvent
	//
	// Len returns the size of the list, namely the number of events
	// it contains. Using Len coupled with Get allows iterating over
	// all the events of the list.
	Len() int
	//
	// Free takes care of de-allocating all the memory managed by
	// instances of PluginEvents. Note that using the same instance
	// after invoking its Free method might lead to non-determinitic
	// behavior.
	Free()
	//
	// ArrayPtr return an unsafe pointer to the underlying C array of
	// ss_plugin_event. The returned pointer should only be used for
	// read tasks or for being passed to the plugin framework.
	// Writing in the memory pointed by this pointer is unsafe and might
	// lead to non-deterministic behavior.
	ArrayPtr() unsafe.Pointer
}
type pluginEvent struct {
	data        BytesReadWriter
	dataSize    int64
	ssPluginEvt unsafe.Pointer
}

type pluginEvents []*pluginEvent

// NewPluginEvents creates a new instance of sdk.PluginEvents.
// The size argument indicates the length of the list, which is the amount
// of events contained. Then dataSize argument indicates the maximum data
// size of each event.
func NewPluginEvents(size, dataSize int64) (PluginEvents, error) {
	if size < 1 || size > MaxNextBatchEvents {
		return nil, fmt.Errorf("invalid size: %d", size)
	}
	if dataSize < 0 || dataSize > math.MaxInt {
		return nil, fmt.Errorf("invalid dataSize: %d", dataSize)
	}

	ret := (pluginEvents)(make([]*pluginEvent, size))
	pluginEvtArray := (*C.ss_plugin_event)(C.malloc((C.ulong)(size * C.sizeof_ss_plugin_event)))
	var err error
	for i := range ret {
		// get i-th element of pluginEvtArray
		evtPtr := unsafe.Pointer(uintptr(unsafe.Pointer(pluginEvtArray)) + uintptr(i*C.sizeof_ss_plugin_event))
		if ret[i], err = newPluginEvent(evtPtr, dataSize); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (p pluginEvents) Get(eventIndex int) PluginEvent {
	return p[eventIndex]
}

func (p pluginEvents) Len() int {
	return len(p)
}

func (p pluginEvents) Free() {
	for _, pe := range p {
		pe.free()
	}
	C.free( /*(*C.ss_plugin_event)*/ p.ArrayPtr())
}

func (p pluginEvents) ArrayPtr() unsafe.Pointer {
	return p[0].ssPluginEvt
}

func newPluginEvent(evtPtr unsafe.Pointer, dataSize int64) (*pluginEvent, error) {
	evt := (*C.ss_plugin_event)(evtPtr)
	evt.ts = C.ulong(math.MaxUint64)
	// todo(jasondellaluce, leogr): optimize this to leverage memory locality.
	evt.data = (*C.uchar)(C.malloc(C.size_t(dataSize)))
	evt.datalen = 0
	brw, err := NewBytesReadWriter(unsafe.Pointer(evt.data), int64(dataSize))

	if err != nil {
		return nil, err
	}

	return &pluginEvent{
		ssPluginEvt: evtPtr,
		data:        brw,
		dataSize:    dataSize,
	}, nil
}

func (p *pluginEvent) Reader() io.ReadSeeker {
	p.data.SetSize(int64((*C.ss_plugin_event)(p.ssPluginEvt).datalen))
	p.data.Seek(0, io.SeekStart)
	return p.data
}

func (p *pluginEvent) Writer() io.Writer {
	p.data.SetSize(p.dataSize)
	p.data.Seek(0, io.SeekStart)
	(*C.ss_plugin_event)(p.ssPluginEvt).datalen = 0
	return p
}

func (p *pluginEvent) Write(data []byte) (n int, err error) {
	n, err = p.data.Write(data)
	if err != nil {
		return
	}
	(*C.ss_plugin_event)(p.ssPluginEvt).datalen += C.uint(n)
	return
}

func (p *pluginEvent) SetTimestamp(value uint64) {
	(*C.ss_plugin_event)(p.ssPluginEvt).ts = C.ulong(value)
}

func (p *pluginEvent) free() {
	C.free(unsafe.Pointer((*C.ss_plugin_event)(p.ssPluginEvt).data))
	p.data = nil
}
