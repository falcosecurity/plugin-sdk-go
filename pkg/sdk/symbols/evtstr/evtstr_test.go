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

package evtstr

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errDataMatch = errors.New("data does not match")
var errTest = errors.New("test err")
var strSuccess = "success"

type sampleEvtStr struct {
	strBuf       ptr.StringBuffer
	shouldError  bool
	expectedData []byte
}

func (s *sampleEvtStr) StringerBuffer() sdk.StringBuffer {
	return &s.strBuf
}

func (s *sampleEvtStr) String(in io.ReadSeeker) (string, error) {
	if s.shouldError {
		return "", errTest
	}
	data, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(s.expectedData, data) {
		return "", errDataMatch
	}

	return strSuccess, nil
}

func TestEvtStr(t *testing.T) {
	sample := &sampleEvtStr{}
	defer sample.StringerBuffer().Free()
	handle := cgo.NewHandle(sample)
	defer handle.Delete()

	data := []byte{0, 1, 2, 3, 4, 5, 6}
	sample.expectedData = data

	// test success
	cStr := plugin_event_to_string(_Ctype_uintptr_t(handle), (*_Ctype_uint8_t)(&data[0]), uint32(len(data)))
	str := ptr.GoString(unsafe.Pointer(cStr))
	if str != strSuccess {
		t.Errorf("expected %s, but found %s", strSuccess, str)
	}

	// test forced error
	sample.shouldError = true
	cStr = plugin_event_to_string(_Ctype_uintptr_t(handle), (*_Ctype_uint8_t)(&data[0]), uint32(len(data)))
	str = ptr.GoString(unsafe.Pointer(cStr))
	if str != errTest.Error() {
		t.Errorf("expected %s, but found %s", strSuccess, str)
	}
}
