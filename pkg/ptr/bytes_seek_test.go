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

package ptr

import (
	"io"
	"testing"
)

// The BytesReadWriter interface documents "0 <= Offset() <= Len()", and the
// SeekCurrent and SeekEnd branches both validate before moving the cursor. A
// rejected SeekStart has to behave the same way, or the cursor is left outside
// the buffer and every later relative seek fails.
func TestBytesReadWriterRejectedSeekStartKeepsCursor(t *testing.T) {
	_, brw, err := createAndWrapBytes(128, byte(10))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := brw.Seek(5, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	if _, err := brw.Seek(brw.Len()+1, io.SeekStart); err == nil {
		t.Fatal("seeking past the end of the buffer should return an error")
	}

	if got := brw.Offset(); got != 5 {
		t.Errorf("Offset() after a rejected SeekStart = %d, want 5", got)
	}
	if got, limit := brw.Offset(), brw.Len(); got > limit {
		t.Errorf("Offset() = %d is outside the documented range 0..Len() = %d", got, limit)
	}

	if pos, err := brw.Seek(1, io.SeekCurrent); err != nil {
		t.Errorf("SeekCurrent after a rejected SeekStart returned %v", err)
	} else if pos != 6 {
		t.Errorf("SeekCurrent after a rejected SeekStart = %d, want 6", pos)
	}
}
