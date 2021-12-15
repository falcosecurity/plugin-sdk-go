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

package read

import (
	"errors"
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = errors.New("testErr")

type sampleRead struct {
	data    []byte
	err     error
	lastErr error
}

func (s *sampleRead) Read(p []byte) (n int, err error) {
	if s.err != nil {
		n = 0
		err = s.err
		return
	}

	for n = 0; n < len(p) && n < len(s.data); n++ {
		p[n] = s.data[n]
	}

	if n > 0 {
		s.data = s.data[n:]
	}

	if len(s.data) == 0 {
		err = sdk.ErrEOF
	}

	return
}

func (s *sampleRead) SetLastError(err error) {
	s.lastErr = err
}

func (s *sampleRead) LastError() error {
	return s.lastErr
}

func assertPanic(t *testing.T, fun func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	fun()
}

func createTestData(size int) []byte {
	res := make([]byte, size)
	for i := 0; i < size; i++ {
		res[i] = (byte)(i % 256)
	}
	return res
}

func TestReadPanic(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		handle := cgo.NewHandle(5)
		defer handle.Delete()
		assertPanic(t, func() {
			test("panic-1", handle, handle, 600, int(sdk.SSPluginSuccess), 600)
		})
	})
}

func TestReadRegular(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		sample := &sampleRead{
			data: createTestData(1000),
		}
		handle := cgo.NewHandle(sample)
		defer handle.Delete()
		test("regular-1", handle, handle, 600, int(sdk.SSPluginSuccess), 600)
		test("regular-2", handle, handle, 600, int(sdk.SSPluginEOF), 400)
		test("regular-3", handle, handle, 600, int(sdk.SSPluginEOF), 0)
	})
}

func TestReadUnsufficient(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		sample := &sampleRead{
			data: createTestData(10),
		}
		handle := cgo.NewHandle(sample)
		defer handle.Delete()
		test("unsufficient-1", handle, handle, 20, int(sdk.SSPluginEOF), 10)
	})
}

func TestReadStressBuffering(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		sample := &sampleRead{
			// This should be larger than the underlying C buffer,
			// and should cause multiple buffer refills.
			data: createTestData(128 * 1024),
		}
		handle := cgo.NewHandle(sample)
		defer handle.Delete()
		test("buffering-1", handle, handle, 80*1024, int(sdk.SSPluginSuccess), 80*1024)
		test("buffering-2", handle, handle, 60*1024, int(sdk.SSPluginEOF), 48*1024)
		test("buffering-3", handle, handle, 40*1024, int(sdk.SSPluginEOF), 0)
	})
}

func TestReadBigChunk(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		sample := &sampleRead{
			data: createTestData(256 * 1024),
		}
		handle := cgo.NewHandle(sample)
		defer handle.Delete()
		test("big-chunk-1", handle, handle, 256*1024, int(sdk.SSPluginEOF), 256*1024)
		test("big-chunk-2", handle, handle, 1, int(sdk.SSPluginEOF), 0)
	})
}

func TestReadTimeout(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		sample := &sampleRead{
			data: createTestData(10),
			err:  sdk.ErrTimeout,
		}
		handle := cgo.NewHandle(sample)
		defer handle.Delete()
		test("timeout-1", handle, handle, 20, int(sdk.SSPluginTimeout), 0)
		test("timeout-2", handle, handle, 40, int(sdk.SSPluginTimeout), 0)
		sample.err = nil
		test("timeout-3", handle, handle, 10, int(sdk.SSPluginEOF), 10)
	})
}

func TestReadError(t *testing.T) {
	doUnitTest(t, func(test unitTestCaseFunc) {
		sample := &sampleRead{
			err: errTest,
		}
		handle := cgo.NewHandle(sample)
		defer handle.Delete()
		test("error-1", handle, handle, 10, int(sdk.SSPluginFailure), 0)
		if sample.LastError() != errTest {
			errStr := "nil"
			if sample.LastError() != nil {
				errStr = sample.LastError().Error()
			}
			t.Errorf("expected error '%s', but found '%s'", errTest.Error(), errStr)
		}
	})
}
