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

package ptr

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"reflect"
	"testing"
	"unsafe"
)

// Creates a byte slice of the given length, fills it with the given value,
// and wraps it with a BytesReadWriter.
func createAndWrapBytes(length int, fill byte) ([]byte, BytesReadWriter, error) {
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = fill
	}
	bytesPtr := unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Data)
	bytesReadWriter, err := NewBytesReadWriter(bytesPtr, int64(length), int64(length))
	return bytes, bytesReadWriter, err
}

func TestNewBytesReadWriter(t *testing.T) {
	var err error

	// Test nil buffer
	_, err = NewBytesReadWriter(nil, 10, 10)
	if err == nil {
		t.Errorf("Buffer argument is not properly checked")
	}

	// Test invalid capacity value
	bytes := make([]byte, 10)
	bytesPtr := unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&bytes)).Data)
	_, err = NewBytesReadWriter(bytesPtr, 10, -1)
	if err == nil {
		t.Errorf("Capacity argument is not properly checked")
	}

	// Test invalid length value
	_, err = NewBytesReadWriter(bytesPtr, -1, 10)
	if err == nil {
		t.Errorf("Length argument is not properly checked")
	}

	_, err = NewBytesReadWriter(bytesPtr, 11, 10)
	if err == nil {
		t.Errorf("Length argument is not properly checked")
	}
}

func TestBytesReadWriterPointer(t *testing.T) {
	// Allocate a memory buffer and wrap it in a BytesReadWriter
	bytesFillValue := byte(10)
	bytes, bytesReadWriter, err := createAndWrapBytes(128, bytesFillValue)
	if err != nil {
		t.Error(err)
	}

	// The bytesReadWriter should read the contents of the buffer
	tmp := []byte{0}
	n, err := bytesReadWriter.Read(tmp)
	if err != nil {
		t.Error(err)
	} else if n != len(tmp) {
		t.Errorf("Expected %d bytes, but found %d", len(tmp), n)
	} else if tmp[0] != bytesFillValue {
		t.Errorf("Expected %d value, but found %d", bytesFillValue, tmp[0])
	}

	// Editing buffer should make bytesReadWriter change too
	// because they point to the same memory location
	editPos := 0
	editByte := byte('X')
	bytes[editPos] = editByte
	_, err = bytesReadWriter.Seek(int64(editPos), io.SeekStart)
	if err != nil {
		t.Error(err)
	}
	_, err = bytesReadWriter.Read(tmp)
	if err != nil {
		t.Error(err)
	} else if tmp[0] != editByte {
		t.Errorf("Expected %d value, but found %d", editByte, tmp[0])
	}

	// Check that Buffer returns a correct pointer
	if unsafe.Pointer(&bytes[0]) != bytesReadWriter.BufferPtr() {
		t.Errorf("BufferPtr() does not return the correct pointer")
	}
}

func TestBytesReadWriterSeek(t *testing.T) {
	// Allocate a memory buffer and wrap it in a BytesReadWriter
	_, bytesReadWriter, err := createAndWrapBytes(128, byte(10))
	if err != nil {
		t.Error(err)
	}

	pos, err := bytesReadWriter.Seek(5, io.SeekStart)
	if err != nil {
		t.Error(err)
	} else if pos != 5 {
		t.Errorf("wrong seek result (SeekStart): expected %d, but found %d", 5, pos)
	}

	pos, err = bytesReadWriter.Seek(10, io.SeekCurrent)
	if err != nil {
		t.Error(err)
	} else if pos != 15 {
		t.Errorf("wrong seek result (SeekCurrent): expected %d, but found %d", 15, pos)
	}

	pos, err = bytesReadWriter.Seek(0, io.SeekEnd)
	if err != nil {
		t.Error(err)
	} else if pos != 128 {
		t.Errorf("wrong seek result (SeekEnd): expected %d, but found %d", 128, pos)
	}

	// Wrong whence
	_, err = bytesReadWriter.Seek(0, io.SeekEnd+1)
	if err == nil {
		t.Errorf("err should not be nil")
	}

	// Negative offset
	_, err = bytesReadWriter.Seek(-1, io.SeekStart)
	if err == nil {
		t.Errorf("err should not be nil")
	}

	// Going beyond the buffer len (SeekCurrent)
	_, err = bytesReadWriter.Seek(1, io.SeekCurrent)
	if err == nil {
		t.Errorf("err should not be nil")
	}

	// Going beyond the buffer len (SeekEnd)
	_, err = bytesReadWriter.Seek(129, io.SeekEnd)
	if err == nil {
		t.Errorf("err should not be nil")
	}

	// Going beyond the buffer len (SeekStart)
	_, err = bytesReadWriter.Seek(129, io.SeekStart)
	if err == nil {
		t.Errorf("err should not be nil")
	}
}

func TestBytesReadWriterReadAll(t *testing.T) {
	// Allocate a memory buffer and wrap it in a BytesReadWriter
	bytesFillValue := byte(10)
	bytes, bytesReadWriter, err := createAndWrapBytes(128, bytesFillValue)
	if err != nil {
		t.Error(err)
	}

	// Read the whole buffer and check for the expected content
	res, err := ioutil.ReadAll(bytesReadWriter)
	if err != nil {
		t.Error(err)
	} else if len(res) != len(bytes) {
		t.Errorf("Expected reading %d bytes, but found %d", len(bytes), len(res))
	} else if int(bytesReadWriter.Offset()) != len(bytes) {
		t.Errorf("Expected offset %d, but found %d", len(bytes), len(res))
	}
	for i, b := range res {
		if b != bytesFillValue {
			t.Errorf("Expected %d value at position %d, but found %d", bytesFillValue, i, b)
		}
	}
}

func TestBytesReadWriterEncodeDecode(t *testing.T) {
	// Allocate a memory buffer and wrap it in a BytesReadWriter
	_, bytesReadWriter, err := createAndWrapBytes(2048, byte(0))
	if err != nil {
		t.Error(err)
	}

	// Encode a value using the json encoder
	value := "test string"
	encoder := json.NewEncoder(bytesReadWriter)
	err = encoder.Encode(value)
	if err != nil {
		t.Error(err)
	}

	// Decode the value and check for correctness
	var outValue string
	bytesReadWriter.Seek(0, io.SeekStart)
	decoder := json.NewDecoder(bytesReadWriter)
	err = decoder.Decode(&outValue)
	if err != nil {
		t.Error(err)
	}
	if outValue != value {
		t.Errorf("Expected '%s' value, but found '%s'", value, outValue)
	}
}

func TestBytesReadWriterSetLen(t *testing.T) {
	// Create a BytesReadWriter with a given length
	length := 128
	_, bytesReadWriter, err := createAndWrapBytes(length, byte(0))
	if err != nil {
		t.Error(err)
	}

	// Check that length is properly set
	if int(bytesReadWriter.Len()) != length {
		t.Errorf("Expected %d value, but found %d", length, bytesReadWriter.Len())
	}

	// Check that a length larger than the capacity is properly bounded
	bytesReadWriter.SetLen(256)
	if int(bytesReadWriter.Len()) != length {
		t.Errorf("Expected %d value, but found %d", length, bytesReadWriter.Len())
	}

	// Check that a length below zero than the capacity is properly bounded
	bytesReadWriter.SetLen(-5)
	if int(bytesReadWriter.Len()) != 0 {
		t.Errorf("Expected %d value, but found %d", 0, bytesReadWriter.Len())
	}

	// Check that a lenght smaller than the capacity is properly set
	bytesReadWriter.SetLen(64)
	if int(bytesReadWriter.Len()) != 64 {
		t.Errorf("Expected %d value, but found %d", 64, bytesReadWriter.Len())
	}
}

func TestBytesReadWriterOffset(t *testing.T) {
	// Create a BytesReadWriter
	_, bytesReadWriter, err := createAndWrapBytes(128, byte(0))
	if err != nil {
		t.Error(err)
	}

	// Read a buffer and check if offset is updated accordingly.
	// This also ensures that the offset is not positioned at the start of
	// the buffer at creation.
	tmp := make([]byte, 32)
	n, err := bytesReadWriter.Read(tmp)
	if err != nil {
		t.Error(err)
	} else if n != len(tmp) {
		t.Errorf("Expected reading %d bytes, but found %d", len(tmp), n)
	} else if int(bytesReadWriter.Offset()) != len(tmp) {
		t.Errorf("Expected %d offset, but found %d", len(tmp), bytesReadWriter.Offset())
	}

	// Write a buffer and check if offset is updated accordingly
	n, err = bytesReadWriter.Write(tmp)
	if err != nil {
		t.Error(err)
	} else if n != len(tmp) {
		t.Errorf("Expected reading %d bytes, but found %d", len(tmp), n)
	} else if int(bytesReadWriter.Offset()) != 2*len(tmp) {
		t.Errorf("Expected %d offset, but found %d", 2*len(tmp), bytesReadWriter.Offset())
	}
}
