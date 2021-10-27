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

package lasterr

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = fmt.Errorf("test")

type pluginContext struct {
	lastErrBuf ptr.StringBuffer
	lastErr    error
}

func (p *pluginContext) LastError() error {
	return p.lastErr
}

func (p *pluginContext) SetLastError(err error) {
	p.lastErr = err
}

func (p *pluginContext) LastErrorBuffer() sdk.StringBuffer {
	return &p.lastErrBuf
}

func TestLastErr(t *testing.T) {
	pCtx := &pluginContext{}
	pCtx.SetLastError(errTest)
	p := cgo.NewHandle(pCtx)

	cStr := plugin_get_last_error(_Ctype_uintptr_t(p))
	errStr := ptr.GoString(unsafe.Pointer(cStr))

	if errTest.Error() != errStr {
		t.Fatalf(`expected: "%s" - got: "%s"`, errTest.Error(), errStr)
	}
}
