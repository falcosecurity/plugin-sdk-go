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

package nextbatch

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = errors.New("testErr")

type sampleNextBatch struct {
	events  sdk.EventWriters
	n       int
	err     error
	lastErr error
}

func (s *sampleNextBatch) Events() sdk.EventWriters {
	return s.events
}

func (s *sampleNextBatch) SetEvents(evts sdk.EventWriters) {
	s.events = evts
}

func (s *sampleNextBatch) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	return s.n, s.err
}

func (s *sampleNextBatch) SetLastError(err error) {
	s.lastErr = err
}

func (s *sampleNextBatch) LastError() error {
	return s.lastErr
}

func TestNextBatch(t *testing.T) {
	sample := &sampleNextBatch{}
	handle := cgo.NewHandle(sample)
	defer handle.Delete()
	events, err := sdk.NewEventWriters(10, 10)
	if err != nil {
		t.Error(err)
	}
	defer events.Free()
	sample.events = events

	// generic testing callback
	doTest := func(name string, res int32, num uint32, ptr unsafe.Pointer, err error) {
		var resNum uint32
		var resPtr **_Ctype_ss_plugin_event
		r := plugin_next_batch(_Ctype_uintptr_t(handle), _Ctype_uintptr_t(handle), &resNum, &resPtr)
		if r != res {
			t.Errorf("(%s - res): expected %d, but found %d", name, res, r)
		} else if resNum != num {
			t.Errorf("(%s - num): expected %d, but found %d", name, num, resNum)
		} else if unsafe.Pointer(resPtr) != ptr {
			t.Errorf("(%s - ptr): expected %d, but found %d", name, ptr, resPtr)
		} else if sample.lastErr != err {
			if sample.lastErr == nil && err != nil {
				t.Errorf("(%s - err): should not be nil", name)
			} else if err == nil {
				t.Errorf("(%s - err): should be nil", name)
			} else {
				t.Errorf("(%s - err): expected %s, but found %s", name, err.Error(), sample.lastErr.Error())
			}
		}
	}

	// success
	sample.n = 5
	sample.err = nil
	doTest("success", sdk.SSPluginSuccess, uint32(sample.n), events.ArrayPtr(), nil)

	// timeout
	sample.n = 5
	sample.err = sdk.ErrTimeout
	doTest("timeout", sdk.SSPluginTimeout, uint32(sample.n), events.ArrayPtr(), nil)

	// eof
	sample.n = 5
	sample.err = sdk.ErrEOF
	doTest("timeout", sdk.SSPluginEOF, uint32(sample.n), events.ArrayPtr(), nil)

	// failure
	sample.n = 0
	sample.err = errTest
	doTest("failure", sdk.SSPluginFailure, uint32(sample.n), nil, errTest)

}
