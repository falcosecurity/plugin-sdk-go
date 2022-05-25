/*
Copyright (C) 2022 The Falco Authors.

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

func TestPullInstance(t *testing.T) {
	timeout := time.Millisecond * 10

	// create batch
	batch := &sdk.InMemoryEventWriters{}
	for i := 0; i < sdk.DefaultBatchSize; i++ {
		batch.Writers = append(batch.Writers, &sdk.InMemoryEventWriter{})
	}

	// setup evt generation callback
	nEvt := 0
	pull := func(c context.Context, s sdk.PluginState, e sdk.EventWriter) error {
		if nEvt == 0 {
			time.Sleep(timeout * 10)
		}
		if nEvt == 3 {
			return sdk.ErrEOF
		}
		nEvt++
		e.Writer().Write(createEventData(100))
		return nil
	}

	// setup closing callback
	closed := false
	close := func() { closed = true }

	// open instance
	inst, err := OpenPullInstance(
		pull,
		WithInstanceTimeout(timeout),
		WithInstanceClose(close),
	)
	if err != nil {
		t.Fatal(err.Error())
	}

	// fist call to nextbatch should trigger the timeout and return 1 evt
	n, err := inst.NextBatch(nil, batch)
	if err != sdk.ErrTimeout {
		t.Fatalf("expected sdk.ErrTimeout, but found error: %s ", err)
	} else if n != 1 {
		t.Fatalf("expected %d, but found %d", 1, n)
	}

	// second call to nextbatch should trigger the EOF and return 2 evts
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 2 {
		t.Fatalf("expected %d, but found %d", 2, n)
	}

	// close instance
	closer, ok := inst.(sdk.Closer)
	if !ok {
		t.Fatalf("instance does not implement sdk.Closer")
	}
	closer.Close()
	if !closed {
		t.Fatalf("expected close callback to be invoked")
	}

	// every other call should return EOF
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}
}

func TestPullInstanceCtxCanceling(t *testing.T) {
	// create batch
	batch := &sdk.InMemoryEventWriters{}
	for i := 0; i < sdk.DefaultBatchSize; i++ {
		batch.Writers = append(batch.Writers, &sdk.InMemoryEventWriter{})
	}

	ctx, cancel := context.WithCancel(context.Background())
	pull := func(c context.Context, s sdk.PluginState, e sdk.EventWriter) error {
		return sdk.ErrTimeout
	}
	inst, err := OpenPullInstance(pull, WithInstanceContext(ctx))
	if err != nil {
		t.Fatal(err.Error())
	}

	// fist call to nextbatch should trigger the timeout and return no evts
	n, err := inst.NextBatch(nil, batch)
	if err != sdk.ErrTimeout {
		t.Fatalf("expected sdk.ErrTimeout, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}

	// cancel context
	cancel()

	// next call to nextbatch should trigger EOF
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}
}

func TestPushInstance(t *testing.T) {
	timeout := time.Millisecond * 100

	// create batch
	batch := &sdk.InMemoryEventWriters{}
	for i := 0; i < sdk.DefaultBatchSize; i++ {
		batch.Writers = append(batch.Writers, &sdk.InMemoryEventWriter{})
	}

	// setup evt generation worker
	evtChan := make(chan PushEvent)
	waitChan := make(chan bool)
	defer close(evtChan)
	defer close(waitChan)
	go func() {
		data := createEventData(100)
		evtChan <- PushEvent{Data: data}
		<-waitChan // trigger timeout at first event
		evtChan <- PushEvent{Data: data}
		evtChan <- PushEvent{Data: data}
		evtChan <- PushEvent{Err: sdk.ErrEOF}
	}()

	// setup closing callback
	closed := false
	close := func() { closed = true }

	// open instance
	inst, err := OpenPushInstance(
		evtChan,
		WithInstanceTimeout(timeout),
		WithInstanceClose(close),
	)
	if err != nil {
		t.Fatal(err.Error())
	}

	// fist call to nextbatch should trigger the timeout and return evts
	n, err := inst.NextBatch(nil, batch)
	if err != sdk.ErrTimeout {
		t.Fatalf("expected sdk.ErrTimeout, but found error: %s ", err)
	} else if n != 1 {
		t.Fatalf("expected %d, but found %d", 1, n)
	}
	waitChan <- true

	// second call to nextbatch should trigger the EOF and return 2 evts
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 2 {
		t.Fatalf("expected %d, but found %d", 2, n)
	}

	// close instance
	closer, ok := inst.(sdk.Closer)
	if !ok {
		t.Fatalf("instance does not implement sdk.Closer")
	}
	closer.Close()
	if !closed {
		t.Fatalf("expected close callback to be invoked")
	}

	// every other call should return EOF
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}
}

func TestPushInstanceChanClosing(t *testing.T) {
	// create batch
	batch := &sdk.InMemoryEventWriters{}
	for i := 0; i < sdk.DefaultBatchSize; i++ {
		batch.Writers = append(batch.Writers, &sdk.InMemoryEventWriter{})
	}

	evtChan := make(chan PushEvent)
	inst, err := OpenPushInstance(evtChan)
	if err != nil {
		t.Fatal(err.Error())
	}

	// fist call to nextbatch should trigger the timeout and return no evts
	n, err := inst.NextBatch(nil, batch)
	if err != sdk.ErrTimeout {
		t.Fatalf("expected sdk.ErrTimeout, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}

	// close channel
	close(evtChan)

	// next call to nextbatch should trigger EOF
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}
}

func TestPushInstanceCtxCanceling(t *testing.T) {
	// create batch
	batch := &sdk.InMemoryEventWriters{}
	for i := 0; i < sdk.DefaultBatchSize; i++ {
		batch.Writers = append(batch.Writers, &sdk.InMemoryEventWriter{})
	}

	ctx, cancel := context.WithCancel(context.Background())
	evtChan := make(chan PushEvent)
	defer close(evtChan)
	inst, err := OpenPushInstance(evtChan, WithInstanceContext(ctx))
	if err != nil {
		t.Fatal(err.Error())
	}

	// fist call to nextbatch should trigger the timeout and return no evts
	n, err := inst.NextBatch(nil, batch)
	if err != sdk.ErrTimeout {
		t.Fatalf("expected sdk.ErrTimeout, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}

	// cancel context
	cancel()

	// next call to nextbatch should trigger EOF
	n, err = inst.NextBatch(nil, batch)
	if err != sdk.ErrEOF {
		t.Fatalf("expected sdk.ErrEOF, but found error: %s ", err)
	} else if n != 0 {
		t.Fatalf("expected %d, but found %d", 0, n)
	}
}
