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
	"io/ioutil"
	"testing"
	"time"
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

func allocSSPluginEvent(num, ts uint64, data []byte) (*_Ctype_struct_ss_plugin_event, func()) {
	ret := &_Ctype_struct_ss_plugin_event{}
	ret.evtnum = _Ctype_uint64_t(num)
	ret.ts = _Ctype_uint64_t(ts)
	ret.data = (*_Ctype_uint8_t)(&data[0])
	ret.datalen = _Ctype_uint32_t(len(data))

	return ret, func() {
		// nothing to deallocate here
	}
}

func (s *sampleEvtStr) StringerBuffer() sdk.StringBuffer {
	return &s.strBuf
}

func (s *sampleEvtStr) String(evt sdk.EventReader) (string, error) {
	if s.shouldError {
		return "", errTest
	}
	data, err := ioutil.ReadAll(evt.Reader())
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
	event, freeEvent := allocSSPluginEvent(1, uint64(time.Now().UnixNano()), data)
	defer freeEvent()
	cStr := plugin_event_to_string(_Ctype_uintptr_t(handle), event)
	str := ptr.GoString(unsafe.Pointer(cStr))
	if str != strSuccess {
		t.Errorf("expected %s, but found %s", strSuccess, str)
	}

	// test forced error
	sample.shouldError = true
	cStr = plugin_event_to_string(_Ctype_uintptr_t(handle), event)
	str = ptr.GoString(unsafe.Pointer(cStr))
	if str != errTest.Error() {
		t.Errorf("expected %s, but found %s", strSuccess, str)
	}
}
