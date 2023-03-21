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

// TODO(jasondellaluce): add docs for this
package metrics

/*
#include "../../plugin_types.h"
*/
import "C"
import (
	"fmt"
	"os"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

//export plugin_get_metrics
func plugin_get_metrics(pState C.uintptr_t, metricsLen *C.uint32_t) *C.ss_plugin_metric {
	fmt.Fprintf(os.Stdout, "HELLO\n")
	if m, ok := cgo.Handle(pState).Value().(sdk.Metrics); ok && m.MetricFactory() != nil {
		*metricsLen = (C.uint32_t)(m.MetricFactory().Len())
		return (*C.ss_plugin_metric)(m.MetricFactory().Buf())
	}
	*metricsLen = 0
	return nil
}
