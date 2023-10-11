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

package asyncbench

import (
	"testing"
)

func TestWorker(t *testing.T) {
	var lock int32
	startWorker(&lock)

	inData = testInput
	dataRequest(&lock)
	if outData != expectedOut {
		t.Fatalf(`dataRequest failed: expected "%d", got "%d"`, expectedOut, outData)
	}

	exitRequest(&lock)
}

func BenchmarkCall_Go(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = doWork(testInput)
	}
}

func BenchmarkCall_C_to_Go(b *testing.B) {
	benchmark_sync(b.N, testInput)
}

func BenchmarkCall_Go_to_C(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = do_work_c(testInput)
	}
}

func BenchmarkWorker_GoCaller(b *testing.B) {
	var lock int32
	startWorker(&lock)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dataRequest(&lock)
	}
	b.StopTimer()
	exitRequest(&lock)
}

func BenchmarkWorker_CCaller(b *testing.B) {
	var lock int32
	startWorker(&lock)
	b.ResetTimer()
	benchmark_async(&lock, b.N)
	b.StopTimer()
	exitRequest(&lock)
}
