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

/*
#include "plugin_types.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
)

const (
	maxMetrics      = 128
	maxMetricLabels = 128
)

// TODO(jasondellaluce): add docs for this
type Labels map[string]string

// TODO(jasondellaluce): add docs for this
type Counter interface {
	// Add adds the given value to the counter. It panics if the value is < 0.
	Add(float64)
}

// TODO(jasondellaluce): add docs for this
type CounterVec interface {
	Add(Labels, float64)
}

// TODO(jasondellaluce): add docs for this
type Gauge interface {
	// Set sets the Gauge to an arbitrary value.
	Set(float64)
	// Add adds the given value to the Gauge. (The value can be negative,
	// resulting in a decrease of the Gauge.)
	Add(float64)
}

// TODO(jasondellaluce): add docs for this
type GaugeVec interface {
	Set(Labels, float64)
	Add(Labels, float64)
}

// TODO(jasondellaluce): add docs for this
type MetricFactory interface {
	NewCounter(name string) Counter
	NewCounterVec(name string, labelNames []string) CounterVec
	NewGauge(name string) Gauge
	NewGaugeVec(name string, labelNames []string) GaugeVec
	Len() int
	Buf() unsafe.Pointer
}

type discardMetric struct{}

type discardMetricVec struct{}

func (d *discardMetric) Set(float64) {}

func (d *discardMetric) Add(float64) {}

func (d *discardMetricVec) Set(Labels, float64) {}

func (d *discardMetricVec) Add(Labels, float64) {}

func (d *discardMetricVec) Buf() unsafe.Pointer {
	return nil
}

// TODO(jasondellaluce): add docs for this
type DiscardMetricFactory struct {
	m    discardMetric
	mVec discardMetricVec
}

func (d *DiscardMetricFactory) NewCounter(name string) Counter {
	return &d.m
}

func (d *DiscardMetricFactory) NewCounterVec(name string, labelNames []string) CounterVec {
	return &d.mVec
}

func (d *DiscardMetricFactory) NewGauge(name string) Gauge {
	return &d.m
}

func (d *DiscardMetricFactory) NewGaugeVec(name string, labelNames []string) GaugeVec {
	return &d.mVec
}

type metric struct {
	labelNames []string
	m          *C.ss_plugin_metric
	name       ptr.StringBuffer
}

func (m *metric) Add(v float64) {
	if m.m.entries_len == 0 {
		m.m.entries = (*C.ss_plugin_metric_entry)(C.malloc((C.size_t)(C.sizeof_ss_plugin_metric_entry)))
		m.m.entries_len++
	}
	e := (*C.ss_plugin_metric_entry)(unsafe.Pointer(uintptr(unsafe.Pointer(m.m.entries)) + uintptr(0)))
	e.value += C.double(v)
	e.labels_len = 0
}

func (m *metric) Set(v float64) {
	if m.m.entries_len == 0 {
		m.m.entries = (*C.ss_plugin_metric_entry)(C.malloc((C.size_t)(C.sizeof_ss_plugin_metric_entry)))
		m.m.entries_len++
	}
	e := (*C.ss_plugin_metric_entry)(unsafe.Pointer(uintptr(unsafe.Pointer(m.m.entries)) + uintptr(0)))
	e.value = C.double(v)
	e.labels_len = 0
}

type metricsFactory struct {
	ms    *C.ss_plugin_metric
	msLen int
}

func (d *metricsFactory) Buf() unsafe.Pointer {
	return unsafe.Pointer(d.ms)
}

func (d *metricsFactory) Len() int {
	return d.msLen
}

func (d *metricsFactory) NewCounter(name string) Counter {
	ret := &metric{
		m: (*C.ss_plugin_metric)(unsafe.Pointer(uintptr(unsafe.Pointer(d.ms)) + uintptr(d.msLen))),
	}
	d.msLen++
	ret.name.Write(name)
	ret.m.name = (*C.char)(ret.name.CharPtr())
	ret.m._type = (C.ss_plugin_metric_type)(uint32(SSPluginMetricCounter))
	return ret
}
func (d *metricsFactory) NewCounterVec(name string, labelNames []string) CounterVec {
	panic("not implemented")
}

func (d *metricsFactory) NewGauge(name string) Gauge {
	ret := &metric{
		m: (*C.ss_plugin_metric)(unsafe.Pointer(uintptr(unsafe.Pointer(d.ms)) + uintptr(d.msLen))),
	}
	d.msLen++
	ret.name.Write(name)
	ret.m.name = (*C.char)(ret.name.CharPtr())
	ret.m._type = (C.ss_plugin_metric_type)(uint32(SSPluginMetricGauge))
	return ret
}

func (d *metricsFactory) NewGaugeVec(name string, labelNames []string) GaugeVec {
	panic("not implemented")
}

func NewMetricsFactory() MetricFactory {
	return &metricsFactory{
		ms: (*C.ss_plugin_metric)(C.malloc((C.size_t)(C.sizeof_ss_plugin_metric * maxMetrics))),
	}
}
