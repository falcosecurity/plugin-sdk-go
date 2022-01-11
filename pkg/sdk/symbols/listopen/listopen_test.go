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

package listopen

import (
	"encoding/json"
	"errors"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

var errTest = errors.New("errTest")

var sampleParams = []sdk.OpenParam{
	{
		Value: "Res1",
		Desc:  "Desc1",
	},
	{
		Value: "Res2",
	},
}

type sampleOpenParams struct {
	lastErr error
	params  []sdk.OpenParam
	strBuf  ptr.StringBuffer
}

func (b *sampleOpenParams) LastError() error {
	return b.lastErr
}

func (b *sampleOpenParams) SetLastError(err error) {
	b.lastErr = err
}

func (s *sampleOpenParams) OpenParamsBuffer() sdk.StringBuffer {
	return &s.strBuf
}

func (s *sampleOpenParams) OpenParams() ([]sdk.OpenParam, error) {
	return s.params, s.lastErr
}

func TestOpenParams(t *testing.T) {
	var err error
	var bytes []byte
	var res int32
	var str string
	var strExpected string

	// initilize
	pState := &sampleOpenParams{}
	pHandle := cgo.NewHandle(pState)
	defer pHandle.Delete()
	defer pState.strBuf.Free()

	// error
	pState.lastErr = errTest
	str = ptr.GoString(unsafe.Pointer(plugin_list_open_params((_Ctype_uintptr_t)(pHandle), &res)))
	if res != sdk.SSPluginFailure {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginFailure, res)
	} else if pState.LastError() != errTest {
		t.Errorf("(err): expected %s, but found %s", errTest.Error(), pState.LastError().Error())
	} else if str != "" {
		t.Errorf("(value): expected nil, but found %s", str)
	}

	// success
	pState.lastErr = nil
	pState.params = sampleParams
	bytes, err = json.Marshal(&sampleParams)
	if err != nil {
		t.Error(err)
	}
	strExpected = string(bytes)
	str = ptr.GoString(unsafe.Pointer(plugin_list_open_params((_Ctype_uintptr_t)(pHandle), &res)))
	if res != sdk.SSPluginSuccess {
		t.Errorf("(res): expected %d, but found %d", sdk.SSPluginSuccess, res)
	} else if pState.LastError() != nil {
		t.Errorf("(err): expected nil, but found %s", pState.LastError().Error())
	} else if str != strExpected {
		t.Errorf("(value): expected %s, but found %s", strExpected, str)
	}
}
