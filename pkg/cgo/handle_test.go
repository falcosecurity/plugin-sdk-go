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

package cgo

import (
	"reflect"
	"sync/atomic"
	"testing"
)

// This test suite derivates from
// https://cs.opensource.google/go/go/+/refs/tags/go1.17.2:src/runtime/cgo/handle_test.go

func TestHandle(t *testing.T) {
	v := 42

	tests := []struct {
		v1 interface{}
		v2 interface{}
	}{
		{v1: v, v2: v},
		{v1: &v, v2: &v},
		{v1: nil, v2: nil},
	}

	for _, tt := range tests {
		h1 := NewHandle(tt.v1)
		h2 := NewHandle(tt.v2)

		if uintptr(h1) == 0 || uintptr(h2) == 0 {
			t.Fatalf("NewHandle returns zero")
		}

		if uintptr(h1) == uintptr(h2) {
			t.Fatalf("Duplicated Go values should have different handles, but got equal")
		}

		h1v := h1.Value()
		h2v := h2.Value()
		if !reflect.DeepEqual(h1v, h2v) || !reflect.DeepEqual(h1v, tt.v1) {
			t.Fatalf("Value of a Handle got wrong, got %+v %+v, want %+v", h1v, h2v, tt.v1)
		}

		h1.Delete()
		h2.Delete()
	}

	siz := 0
	for i := 0; i < MaxHandle; i++ {
		if atomic.LoadPointer(&handles[i]) != noHandle {
			siz++
		}
	}

	if siz != 0 {
		t.Fatalf("handles are not cleared, got %d, want %d", siz, 0)
	}
}

func TestInvalidHandle(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		h := Handle(0)

		defer func() {
			if r := recover(); r != nil {
				return
			}
			t.Fatalf("Delete of zero handle did not trigger a panic")
		}()

		h.Delete()
	})

	t.Run("zero-value", func(t *testing.T) {
		h := Handle(0)
		defer func() {
			if r := recover(); r != nil {
				return
			}
			t.Fatalf("Delete of zero handle did not trigger a panic")
		}()
		h.Value()
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandle(42)

		defer func() {
			if r := recover(); r != nil {
				h.Delete()
				return
			}
			t.Fatalf("Invalid handle did not trigger a panic")
		}()

		Handle(h + 1).Delete()
	})
}

func TestMaxHandle(t *testing.T) {
	t.Run("non-max", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewHandle with non-max handle count triggered a panic")
			}
		}()
		handles := make([]Handle, 0)
		for i := 1; i <= MaxHandle; i++ {
			v := i
			handles = append(handles, NewHandle(&v))
		}
		for _, h := range handles {
			h.Delete()
		}
	})

	t.Run("max", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				return
			}
			t.Fatalf("NewHandle with max handle count did not triggered a panic")
		}()
		handles := make([]Handle, 0)
		for i := 1; i <= MaxHandle+1; i++ {
			v := i
			handles = append(handles, NewHandle(&v))
		}
		for _, h := range handles {
			h.Delete()
		}
	})
}

func BenchmarkHandle(b *testing.B) {
	b.Run("non-concurrent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := NewHandle(i)
			_ = h.Value()
			h.Delete()

			// reset handle to avoid going out of handle space
			if i%(MaxHandle-1) == 0 {
				resetHandles()
			}
		}
	})
}
