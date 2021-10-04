package sdk

import (
	"encoding/json"
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

func Next(pState unsafe.Pointer, iState unsafe.Pointer, evt PluginEvent) error {
	encoder := json.NewEncoder(evt.Writer())
	err := encoder.Encode(sample)
	if err != nil {
		return err
	}
	evt.SetTimestamp(uint64(time.Now().Unix()) * 1000000000)
	return nil
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
			err := Next(nil, nil, events.Get(j))
			if err != nil {
				println(err.Error())
				b.Fail()
			}
		}
	}
}
