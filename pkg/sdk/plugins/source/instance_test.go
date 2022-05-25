package source

import (
	"bytes"
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

const (
	benchFixedEvtDataSize = 1024
	benchMinEvtDataSize   = 1024
	benchMaxEvtDataSize   = 1 * 1024 * 1204
	benchEvtCount         = 1024
	benchEvtBatchSize     = sdk.DefaultBatchSize
	benchEvtTimeout       = 30 * time.Millisecond
)

func benchNextBatch(b *testing.B, inst Instance, batchSize, evtCount int) {
	batch := &sdk.InMemoryEventWriters{}
	for i := 0; i < batchSize; i++ {
		batch.Writers = append(batch.Writers, &sdk.InMemoryEventWriter{})
	}
	b.ResetTimer()
	tot := 0
	n := 0
	var err error
	for i := 0; i < b.N; i++ {
		tot = 0
		for tot < evtCount {
			n, err = inst.NextBatch(nil, batch)
			if err != nil {
				if err == sdk.ErrEOF {
					break
				}
				if err != sdk.ErrTimeout {
					b.Fatal(err.Error())
				}
			}
			tot += n
		}
	}
	b.StopTimer()
	if closer, ok := inst.(sdk.Closer); ok {
		closer.Close()
	}
}

func benchPullInstance(b *testing.B, onEvt func() []byte) {
	pull := func(c context.Context, s sdk.PluginState, e sdk.EventWriter) error {
		_, err := e.Writer().Write(onEvt())
		return err
	}
	inst, err := OpenPullInstance(pull, WithInstanceTimeout(benchEvtTimeout))
	if err != nil {
		b.Fatal(err.Error())
	}
	benchNextBatch(b, inst, benchEvtBatchSize, benchEvtCount)
}

func benchPushInstance(b *testing.B, onEvt func() []byte) {
	evtChan := make(chan PushEvent)
	stopChan := make(chan bool)
	go func() {
		for {
			select {
			case evtChan <- PushEvent{Data: onEvt()}:
			case <-stopChan:
				return
			}
		}
	}()
	inst, err := OpenPushInstance(evtChan, WithInstanceTimeout(benchEvtTimeout))
	if err != nil {
		b.Fatal(err.Error())
	}
	benchNextBatch(b, inst, benchEvtBatchSize, benchEvtCount)
	stopChan <- true
	close(stopChan)
	close(evtChan)
}

// simulate event generation
func createEventData(size uint32) []byte {
	buf := bytes.Buffer{}
	for size > 0 {
		buf.WriteByte(0)
		size--
	}
	return buf.Bytes()
}

func BenchmarkPullEmpty(b *testing.B) {
	data := []byte{}
	benchPullInstance(b, func() []byte { return data })
}

func BenchmarkPushEmpty(b *testing.B) {
	data := []byte{}
	benchPushInstance(b, func() []byte { return data })
}

func BenchmarkPullFixed(b *testing.B) {
	benchPullInstance(b, func() []byte { return createEventData(benchFixedEvtDataSize) })
}

func BenchmarkPushFixed(b *testing.B) {
	benchPushInstance(b, func() []byte { return createEventData(benchFixedEvtDataSize) })
}

func BenchmarkPullRandom(b *testing.B) {
	benchPullInstance(b, func() []byte {
		return createEventData((rand.Uint32() % (benchMaxEvtDataSize - benchMinEvtDataSize)) + benchMinEvtDataSize)
	})
}

func BenchmarkPushRandom(b *testing.B) {
	benchPushInstance(b, func() []byte {
		return createEventData((rand.Uint32() % (benchMaxEvtDataSize - benchMinEvtDataSize)) + benchMinEvtDataSize)
	})
}
