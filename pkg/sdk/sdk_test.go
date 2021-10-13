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

func nextCallback(pState unsafe.Pointer, iState unsafe.Pointer, evt PluginEvent) error {
	encoder := json.NewEncoder(evt.Writer())
	err := encoder.Encode(sample)
	if err != nil {
		return err
	}
	evt.SetTimestamp(uint64(time.Now().Unix()) * 1000000000)
	return nil
}

func BenchmarkPluginEventsNext(b *testing.B) {
	events, err := NewPluginEvents(1, int64(MaxEvtSize))
	if err != nil {
		println(err.Error())
		b.Fail()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate next
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

func BenchmarkPluginEventsNextBatch(b *testing.B) {
	events, err := NewPluginEvents(MaxNextBatchEvents, int64(MaxEvtSize))
	if err != nil {
		println(err.Error())
		b.Fail()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate next_batch
		for j := 0; j < events.Len(); j++ {
			err := nextCallback(nil, nil, events.Get(j))
			if err != nil {
				println(err.Error())
				b.Fail()
			}
		}
	}
}

func TestPluginEventsWriteRead(t *testing.T) {
	tmp := []byte{0}
	evtNum := MaxNextBatchEvents
	evtSize := MaxEvtSize

	// Create events and fill them with sample data
	events, err := NewPluginEvents(int64(evtNum), int64(evtSize))
	if err != nil {
		t.Error(err)
	}
	for i := 0; i < events.Len(); i++ {
		event := events.Get(i)
		eventWriter := event.Writer()
		for j := 0; j < int(evtSize); j++ {
			n, err := eventWriter.Write(tmp)
			if err != nil {
				t.Error(err)
			} else if n == 0 {
				t.Errorf("Failed writing byte #%d in event %d", j, i)
			}
		}
	}

	// Read every event data sequentially
	for i := 0; i < events.Len(); i++ {
		event := events.Get(i)
		eventReader := event.Reader()
		var j int
		for {
			n, err := eventReader.Read(tmp)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
			} else if n == 0 || tmp[0] != byte(0) {
				t.Errorf("Failed reading byte #%d in event #%d", j, i)
			}
			j++
		}
		if j != int(evtSize) {
			t.Errorf("Expected reading %d bytes, but found %d", evtSize, j)
		}
	}
}
