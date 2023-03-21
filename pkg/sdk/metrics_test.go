// /*
// Copyright (C) 2021 The Falco Authors.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

package sdk

// import (
// 	"bytes"
// 	"encoding/gob"
// 	"reflect"
// 	"testing"

// 	"github.com/prometheus/client_golang/prometheus"
// )

// var labels1 = Labels{
// 	"label1":  "awefwrrvw",
// 	"label3":  "wvfvsfa",
// 	"label2":  "wewefcwvca",
// 	"label4":  "aqwdqwdewdcwd",
// 	"label12": "awdeeffevv,e dlvkqe fvlkqef",
// 	"label32": "aassa,c sxm, sx,m qs ",
// 	"label22": "aasascs",
// 	"label42": "aadcq f.f ve",
// }
// var labels2 = Labels{
// 	"label1":  "awefwrrvw",
// 	"label3":  "wvfvsfa",
// 	"label2":  "wewefcwvca",
// 	"label4":  "aqwdqwdewdcwd",
// 	"label12": "awdeeffevv,e dlvkqe fvlkqef",
// 	"label32": "aassa,c sxm, sx,m qs ",
// 	"label22": "aasascs",
// 	"label42": "aadcq f.f ve",
// }

// func BenchmarkDeepEquals(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		reflect.DeepEqual(labels1, labels2)
// 	}
// }

// func Compare(a, b []byte) bool {
// 	a = append(a, b...)
// 	c := 0
// 	for _, x := range a {
// 		c ^= int(x)
// 	}
// 	return c == 0
// }

// func Hash(s map[string]string) []byte {
// 	var b bytes.Buffer
// 	gob.NewEncoder(&b).Encode(s)
// 	return b.Bytes()
// }

// func BenchmarkHashGobCompare(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		Compare(Hash(labels1), Hash(labels2))
// 	}
// }

// func BenchmarkNaiveCompare(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		if len(labels1) == len(labels2) {
// 			for k, v1 := range labels1 {
// 				v2, ok := labels2[k]
// 				if !ok || v1 != v2 {
// 					b.Fatal()
// 				}
// 			}
// 		} else {
// 			b.Fatal()
// 		}
// 	}
// }

// func BenchmarkMetricVecCompare(b *testing.B) {
// 	l1 := prometheus.Labels(labels1)
// 	var names []string
// 	for k := range labels1 {
// 		names = append(names, k)
// 	}
// 	m := prometheus.NewCounterVec(prometheus.CounterOpts{}, names)
// 	m.Reset()
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		m.GetMetricWith(l1)
// 	}
// }
