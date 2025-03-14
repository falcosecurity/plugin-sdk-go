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

package extract

import (
	"errors"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = errors.New("testErr")

type sampleExtract struct {
	reqs    sdk.ExtractRequestPool
	err     error
	lastErr error
}

func (s *sampleExtract) ExtractRequests() sdk.ExtractRequestPool {
	return s.reqs
}

func (s *sampleExtract) SetExtractRequests(reqs sdk.ExtractRequestPool) {
	s.reqs = reqs
}

func (s *sampleExtract) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	return s.err
}

func (s *sampleExtract) SetLastError(err error) {
	s.lastErr = err
}

func (s *sampleExtract) LastError() error {
	return s.lastErr
}

func allocSSPluginExtractField(fid, ftype uint32, fname, farg string) (*_Ctype_ss_plugin_extract_field, func()) {
	ret := &_Ctype_ss_plugin_extract_field{}
	ret.field_id = _Ctype_uint32_t(fid)
	ret.ftype = _Ctype_uint32_t(ftype)

	argBuf := ptr.StringBuffer{}
	fnameBuf := ptr.StringBuffer{}
	fnameBuf.Write(fname)
	ret.field = (*_Ctype_char)(fnameBuf.CharPtr())
	if len(farg) > 0 {
		argBuf.Write(farg)
		ret.arg_key = (*_Ctype_char)(argBuf.CharPtr())
	} else {
		ret.arg_key = nil
	}

	return ret, func() {
		argBuf.Free()
		fnameBuf.Free()
	}
}

func allocSSPluginExtractValueOffsets(start *uint32, length *uint32) (*_Ctype_ss_plugin_extract_value_offsets) {
	ret := &_Ctype_ss_plugin_extract_value_offsets{}
	ret.start = (*_Ctype_uint32_t)(start)
	ret.length = (*_Ctype_uint32_t)(length)

	return ret
}

func allocSSPluginEvent(num, ts uint64, data []byte) (*_Ctype_struct_ss_plugin_event_input, func()) {
	ret := &_Ctype_struct_ss_plugin_event_input{}
	evts, _ := sdk.NewEventWriters(1, int64(len(data)))
	evt := evts.Get(0)
	evt.Writer().Write(data)
	ret.evt = *(**_Ctype_struct_ss_plugin_event)(evts.ArrayPtr())
	ret.evtnum = _Ctype_uint64_t(num)

	return ret, func() {
		evts.Free()
	}
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}

func TestExtract(t *testing.T) {
	var res int32
	sample := &sampleExtract{}
	handle := cgo.NewHandle(sample)
	defer handle.Delete()
	reqs := sdk.NewExtractRequestPool()
	defer reqs.Free()
	sample.reqs = reqs

	// Alloc c structs
	evtData := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	event, freeEvent := allocSSPluginEvent(1, uint64(time.Now().UnixNano()), evtData)
	defer freeEvent()
	field, freeField := allocSSPluginExtractField(1, sdk.FieldTypeUint64, "test.field", "")
	defer freeField()

	// panic
	badHandle := cgo.NewHandle(1)
	assertPanic(t, func() {
		plugin_extract_fields_sync(_Ctype_uintptr_t(badHandle), event, 1, field, nil)
	})

	// success
	res = plugin_extract_fields_sync(_Ctype_uintptr_t(handle), event, 1, field, nil)
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if sample.lastErr != nil {
		t.Errorf("(lastErr): should be nil")
	}

	// success + offsets
	val_start := uint32(0)
	val_length := uint32(8)
	offsets := allocSSPluginExtractValueOffsets(&val_start, &val_length)
	res = plugin_extract_fields_sync(_Ctype_uintptr_t(handle), event, 1, field, offsets)
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if sample.lastErr != nil {
		t.Errorf("(lastErr): should be nil")
	}

	// error
	sample.err = errTest
	res = plugin_extract_fields_sync(_Ctype_uintptr_t(handle), event, 1, field, nil)
	if res != sdk.SSPluginFailure {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginFailure, res)
	} else if sample.lastErr != errTest {
		t.Errorf("(lastErr): expected %s, but found %s", errTest.Error(), sample.lastErr.Error())
	}
}
