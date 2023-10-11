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

package plugins

import (
	"errors"
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func TestBaseEvents(t *testing.T) {
	b := BaseEvents{}
	value, err := sdk.NewEventWriters(10, 10)
	if err != nil {
		t.Error(err)
	}

	b.SetEvents(value)
	if b.Events() != value {
		t.Errorf("Events: value does not match")
	}
	value.Free()
}

func TestBaseExtractRequests(t *testing.T) {
	b := BaseExtractRequests{}
	value := sdk.NewExtractRequestPool()

	b.SetExtractRequests(value)
	if b.ExtractRequests() != value {
		t.Errorf("ExtractRequests: value does not match")
	}
	value.Free()
}

func TestBaseLastError(t *testing.T) {
	b := BaseLastError{}
	str := "test error"
	value := errors.New(str)

	b.SetLastError(value)
	if b.LastError() != value {
		t.Errorf("LastError: value does not match")
	}

	b.LastErrorBuffer().Write(str)
	if b.LastErrorBuffer().String() != str {
		t.Errorf("LastErrorBuffer: expected %s, but found %s", str, b.LastErrorBuffer().String())
	}
	b.LastErrorBuffer().Free()
}

func TestBaseStringer(t *testing.T) {
	b := BaseStringer{}
	str := "test"

	b.StringerBuffer().Write(str)
	if b.StringerBuffer().String() != str {
		t.Errorf("StringerBuffer: expected %s, but found %s", str, b.StringerBuffer().String())
	}
	b.StringerBuffer().Free()
}

func TestBaseProgress(t *testing.T) {
	b := BaseProgress{}
	str := "test"

	b.ProgressBuffer().Write(str)
	if b.ProgressBuffer().String() != str {
		t.Errorf("ProgressBuffer: expected %s, but found %s", str, b.ProgressBuffer().String())
	}
	b.ProgressBuffer().Free()
}
