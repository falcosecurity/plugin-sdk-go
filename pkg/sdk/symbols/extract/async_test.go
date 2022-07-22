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

package extract

import "testing"

func TestGetMaxWorkers(t *testing.T) {
	expected := []int32{0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5}
	for i, ex := range expected {
		v := getMaxWorkers(i + 1)
		if v != ex {
			t.Fatalf("getMaxWorkers returned %d but expected %d", v, ex)
		}
	}
}
