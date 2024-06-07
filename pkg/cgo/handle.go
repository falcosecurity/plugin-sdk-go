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
	"fmt"
	"sync/atomic"
	"unsafe"
)

// Handle is an alternative implementation of cgo.Handle introduced by
// Go 1.17, see https://pkg.go.dev/runtime/cgo. This implementation
// optimizes performance in use cases related to plugins. It is intended
// to be used both as a replacement and as a polyfill for Go versions
// that miss it.
//
// As the original implementation, this provides a way to pass values that
// contain Go pointers between Go and C without breaking the cgo pointer
// passing rules. The underlying type of Handle is guaranteed to fit in
// an integer type that is large enough to hold the bit pattern of any pointer.
// The zero value of a Handle is not valid and thus is safe to use as
// a sentinel in C APIs.
//
// The performance optimization comes with a limitation: the maximum number
// of valid handles is capped to a fixed value (see MaxHandle).
// However, since the intended usage is to pass opaque pointers holding the
// plugin states (usually at most two pointers per one instance of a plugin),
// this hard limit is considered acceptable.
//
// The thread-safety guarantees have been dropped for further
// performance improvements. The current version of the Plugin API does not
// require thread safety.
//
// The usage in other contexts is discuraged.
type Handle uintptr

const (
	// MaxHandle is the largest value that an Handle can hold
	MaxHandle = 256 - 1

	// max number of times we're willing to iterate over the vector of reusable
	// handles to do compare-and-swap before giving up
	maxNewHandleRounds = 20
)

var (
	handles  [MaxHandle + 1]unsafe.Pointer // [int]*interface{}
	noHandle unsafe.Pointer                = nil
)

func init() {
	resetHandles()
}

// NewHandle returns a handle for a given value.
//
// The handle is valid until the program calls Delete on it. The handle
// uses resources, and this package assumes that C code may hold on to
// the handle, so a program must explicitly call Delete when the handle
// is no longer needed. Programs must not retain deleted handles.
//
// The intended use is to pass the returned handle to C code, which
// passes it back to Go, which calls Value.
//
// The simultaneous number of the valid handles cannot exceed MaxHandle.
// This function panics if there are no more handles available.
// Previously created handles may be made available again when
// invalidated with Delete.
//
// This function is not thread-safe.
func NewHandle(v interface{}) Handle {
	rounds := 0
	for h := uintptr(1); ; h++ {
		// we acquired ownership of an handle, return it
		// note: we attempt accessing slots 1..MaxHandle (included)
		if atomic.CompareAndSwapPointer(&handles[h], noHandle, (unsafe.Pointer)(&v)) {
			return Handle(h)
		}

		// we haven't acquired a handle, but we can try with the next one
		if h < MaxHandle {
			continue
		}

		// we iterated over the whole vector of handles, so we get back to start
		// and try again with another round. Once we do this too many times,
		// we have no choice if not panic-ing
		h = uintptr(0) // note: will be incremented when continuing
		if rounds < maxNewHandleRounds {
			rounds++
			continue
		}

		panic(fmt.Sprintf("plugin-sdk-go/cgo: could not obtain a new handle after round #%d", rounds))
	}
}

// Value returns the associated Go value for a valid handle.
//
// The method panics if the handle is invalid.
// This function is not thread-safe.
func (h Handle) Value() interface{} {
	if h > MaxHandle || atomic.LoadPointer(&handles[h]) == noHandle {
		panic(fmt.Sprintf("plugin-sdk-go/cgo: misuse (value) of an invalid Handle %d", h))
	}
	return *(*interface{})(atomic.LoadPointer(&handles[h]))
}

// Delete invalidates a handle. This method should only be called once
// the program no longer needs to pass the handle to C and the C code
// no longer has a copy of the handle value.
//
// The method panics if the handle is invalid.
// This function is not thread-safe.
func (h Handle) Delete() {
	if h > MaxHandle || atomic.LoadPointer(&handles[h]) == noHandle {
		panic(fmt.Sprintf("plugin-sdk-go/cgo: misuse (delete) of an invalid Handle %d", h))
	}
	atomic.StorePointer(&handles[h], noHandle)
}

func resetHandles() {
	for i := 0; i <= MaxHandle; i++ {
		atomic.StorePointer(&handles[i], noHandle)
	}
}
