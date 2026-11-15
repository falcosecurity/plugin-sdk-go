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

package sdk

import (
	"io"
	"testing"
)

// An extractor reaches the payload cursor through EventReader.Reader(), so a
// seek past the end of the payload has to leave that cursor usable.
func TestEventReaderRejectedSeekLeavesCursorUsable(t *testing.T) {
	const payload = 8

	writers, err := NewEventWriters(1, int64(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer writers.Free()

	evtWriter := writers.Get(0)
	writer := evtWriter.Writer()
	if _, err := writer.Write(make([]byte, payload)); err != nil {
		t.Fatal(err)
	}

	reader := NewEventReader(writers.ArrayPtr()).Reader()
	if _, err := reader.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	if _, err := reader.Seek(payload+1, io.SeekStart); err == nil {
		t.Fatal("seeking past the end of the payload should return an error")
	}

	// The cursor should still be where the last accepted seek left it, so a
	// relative seek and a read both still work.
	if pos, err := reader.Seek(1, io.SeekCurrent); err != nil {
		t.Errorf("SeekCurrent after a rejected seek returned %v", err)
	} else if pos != 3 {
		t.Errorf("SeekCurrent after a rejected seek = %d, want 3", pos)
	}

	buf := make([]byte, 1)
	if n, err := reader.Read(buf); err != nil || n != 1 {
		t.Errorf("Read after a rejected seek returned n=%d err=%v, want n=1 err=nil", n, err)
	}
}
