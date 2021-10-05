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
#include <string.h>
*/
import "C"
import (
	"fmt"
	"io"
	"math"
	"reflect"
	"unsafe"
)

const (
	offsetErrorFmt = "invalid offset value %d"
	sizeErrorFmt   = "invalid size value %d"
	whenceErrorFmt = "invalid whence value %d"
)

// BytesReadWriter is an opaque wrapper for fixed-size memory buffers, that can safely be
// used in the plugin framework ina Go-friendly way. The purpose is to provide means
// for safe memory access through the read/write interface primitives, regardless of how
// how the buffer is physically allocated under the hood. For instance, this can be used
// to wrap a C-allocated buffed, to hide both the type conversion magic and avoid illegal
// memory operations. The io.ReadWriteSeeker interface is leveraged to implement the safe
// random memory access semantic. Note, read-only or rite-only modes to the memory buffer
// can easily be accomplished by casting this to either a io.Reader or io.Writer.
type BytesReadWriter interface {
	io.ReadWriteSeeker
	//
	// Returns an unsafe.Pointer that points to the underlying memory buffer.
	Buffer() unsafe.Pointer
	//
	// Size returns the physical size of the underlying memory buffer.
	Size() int64
	//
	SetSize(size int64)
	//
	// Offser returns the current cursor position relatively to the underlying buffer.
	// The cursor position represents the index of the next byte in the buffer that will
	// be available for read\write operations. This value is altered through the usage of
	// Seek, Read, and Write. By definition, we have that 0 <= Offset() <= Size().
	Offset() int64
	//
	String(len int) string
}

func NewBytesReadWriter(buffer unsafe.Pointer, size int64) (BytesReadWriter, error) {
	if size < 0 || size > math.MaxInt {
		return nil, fmt.Errorf(sizeErrorFmt, size)
	}
	// Inspired by: https://stackoverflow.com/a/66218124
	var bytes []byte
	(*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Data = uintptr(buffer)
	(*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Len = int(size)
	(*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Cap = int(size)
	return &bytesReadWriter{
		buffer:     buffer,
		bytesAlias: bytes,
		offset:     0,
		size:       size,
	}, nil
}

type bytesReadWriter struct {
	offset     int64
	size       int64
	buffer     unsafe.Pointer
	bytesAlias []byte
}

func (b *bytesReadWriter) Read(p []byte) (n int, err error) {
	n = 0
	pLen := len(p)
	for i := 0; i < pLen; i++ {
		if b.offset >= b.size {
			err = io.ErrShortBuffer
			return
		}
		p[i] = b.bytesAlias[b.offset]
		b.offset++
		n++
	}
	return
}

func (b *bytesReadWriter) Write(p []byte) (n int, err error) {
	n = 0
	for _, v := range p {
		if b.offset >= b.size {
			err = io.ErrShortWrite
			return
		}
		b.bytesAlias[b.offset] = v
		b.offset++
		n++
	}
	return
}

func (b *bytesReadWriter) Size() int64 {
	return b.size
}

func (b *bytesReadWriter) SetSize(size int64) {
	b.size = size
}

func (b *bytesReadWriter) Offset() int64 {
	return b.offset
}

func (b *bytesReadWriter) Seek(offset int64, whence int) (int64, error) {
	if offset < 0 {
		return b.offset, fmt.Errorf(offsetErrorFmt, offset)
	}
	switch whence {
	case io.SeekStart:
		b.offset = offset
		if offset > b.size {
			return b.offset, fmt.Errorf(offsetErrorFmt, offset)
		}
	case io.SeekCurrent:
		if offset > b.size-b.offset {
			return b.offset, fmt.Errorf(offsetErrorFmt, offset)
		}
		b.offset = b.offset + offset
	case io.SeekEnd:
		if offset > b.size {
			return b.offset, fmt.Errorf(offsetErrorFmt, offset)
		}
		b.offset = b.size - offset
	default:
		return b.offset, fmt.Errorf(whenceErrorFmt, whence)
	}
	b.offset = offset
	return b.offset, nil
}

func (b *bytesReadWriter) Buffer() unsafe.Pointer {
	return b.buffer
}

func (b *bytesReadWriter) String(len int) string {
	var res string
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Data = uintptr(b.buffer)
	(*reflect.StringHeader)(unsafe.Pointer(&res)).Len = len
	return res
}

func CString(charPtr unsafe.Pointer) string {
	len := int(C.strlen((*C.char)(charPtr)))
	buf, err := NewBytesReadWriter(charPtr, int64(len+1))
	if err != nil {
		// Should we log here?
		return ""
	}
	return buf.String(len)
}
