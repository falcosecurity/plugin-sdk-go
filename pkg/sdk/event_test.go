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

package sdk

import (
	"encoding/json"
	"io"
	"testing"
	"time"
	"unsafe"
)

type sampleEvent struct {
	V1 int
	V2 int
	V3 string
	V4 float64
}

var sample = &sampleEvent{
	V1: 0,
	V2: 2,
	V3: "hello world",
	V4: 5.0,
}

func nextCallback(pState unsafe.Pointer, iState unsafe.Pointer, evt EventWriter) error {
	encoder := json.NewEncoder(evt.Writer())
	err := encoder.Encode(sample)
	if err != nil {
		return err
	}
	evt.SetTimestamp(uint64(time.Now().Unix()) * 1000000000)
	return nil
}

func BenchmarkEventWritersNext(b *testing.B) {
	events, err := NewEventWriters(1, int64(DefaultEvtSize))
	if err != nil {
		println(err.Error())
		b.Fail()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := events.Get(0)
		encoder := json.NewEncoder(event.Writer())
		err = encoder.Encode(sample)
		if err != nil {
			println(err.Error())
			b.Fail()
		}
		event.SetTimestamp(uint64(time.Now().Unix()) * 1000000000)
	}
}

func BenchmarkEventWritersNextBatch(b *testing.B) {
	events, err := NewEventWriters(DefaultBatchSize, int64(DefaultEvtSize))
	if err != nil {
		println(err.Error())
		b.Fail()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < events.Len(); j++ {
			err := nextCallback(nil, nil, events.Get(j))
			if err != nil {
				println(err.Error())
				b.Fail()
			}
		}
	}
}

func TestEventWritersNextBatch(t *testing.T) {
	events, err := NewEventWriters(DefaultBatchSize, int64(DefaultEvtSize))
	if err != nil {
		println(err.Error())
		t.Fail()
	}
	for i := 0; i < events.Len(); i++ {
		err := nextCallback(nil, nil, events.Get(i))
		if err != nil {
			println(err.Error())
			t.Fail()
		}
	}
}

func TestEventWriterEventReader(t *testing.T) {
	tmp := []byte{0}
	evtNum := 1
	evtSize := DefaultEvtSize

	// Create event writer and write sample data
	writers, err := NewEventWriters(int64(evtNum), int64(evtSize))
	if err != nil {
		t.Error(err)
	}
	writer := writers.Get(0).Writer()
	for i := 0; i < int(evtSize); i++ {
		n, err := writer.Write(tmp)
		if err != nil {
			t.Error(err)
		} else if n == 0 {
			t.Errorf("Failed writing byte #%d in event", i)
		}
	}

	// Create event reader and read all data
	reader := NewEventReader(writers.ArrayPtr()).Reader()
	var i int
	for {
		n, err := reader.Read(tmp)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Error(err)
		} else if n == 0 || tmp[0] != byte(0) {
			t.Errorf("Failed reading byte #%d in event", i)
		}
		i++
	}
	if i != int(evtSize) {
		t.Errorf("Expected reading %d bytes, but found %d", evtSize, i)
	}
}
