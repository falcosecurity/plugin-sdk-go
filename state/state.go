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

package state

/*
#include <stdlib.h>

typedef struct {
   void* goMem;
} state;

*/
import "C"
import (
	"sync"
	"unsafe"
)

var peristentPtrs = &sync.Map{}

// NewStateContainer returns an opaque pointer to a memory blob that
// may be safely passed back and forth to the plugin framework.
//
// A state container can reference a Go pointer (suitable for a Go context).
// Both are persisted in memory until manually freed.
// A state container must be manually freed by using Free().
// It can be either used as the state of a source plugin or an open state of the source plugin.
//
func NewStateContainer() unsafe.Pointer {
	pCtx := (*C.state)(C.malloc(C.sizeof_state))
	pCtx.goMem = nil
	return unsafe.Pointer(pCtx)
}

// SetContext sets the given reference ctx (a pointer to any Go managed value) into p,
// assuming p is a state container created with NewStateContainer().
//
// A previously set reference, if any, is removed from p, making it suitable for garbage collecting.
func SetContext(p unsafe.Pointer, ctx unsafe.Pointer) {
	state := (*C.state)(p)

	if state.goMem != nil {
		peristentPtrs.Delete(state.goMem)
	}

	state.goMem = ctx

	if ctx != nil {
		peristentPtrs.Store(ctx, ctx)
	}
}

// Context returns a pointer to Go allocated memory, if any, previously assigned into p with SetContext(),
// assuming p is a state container created with NewStateContainer().
func Context(p unsafe.Pointer) unsafe.Pointer {
	return (*C.state)(p).goMem
}

// Free disposes of any C and Go memory assigned to p and finally free P,
// assuming p is a state container created with NewStateContainer().
func Free(p unsafe.Pointer) {
	SetContext(p, nil)
	C.free(p)
}

