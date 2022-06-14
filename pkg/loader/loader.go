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

package loader

// note: cgo does not support macros and function pointers, so we have to
// create wrappers around those to access them from Go code

/*
#cgo linux LDFLAGS: -ldl
#cgo CFLAGS: -I ../sdk

#include "plugin_loader.h"
#include <stdlib.h>

uint32_t __plugin_max_errlen = PLUGIN_MAX_ERRLEN;

static uint32_t __get_info_u32(uint32_t (*f)())
{
	if (!f) return 0;
    return f();
}

static const char* __get_info_str(const char *(*f)())
{
	if (!f) return "";
    return f();
}

static const char *__get_init_schema(plugin_api* p, ss_plugin_schema_type *s)
{
    return p->get_init_schema(s);
}

static ss_plugin_t* __init(plugin_api* p, const char *cfg, ss_plugin_rc *rc)
{
    return p->init(cfg, rc);
}

static void __destroy(plugin_api* p, ss_plugin_t* s)
{
	p->destroy(s);
}

static const char* __get_last_err(plugin_api* p, ss_plugin_t* s)
{
    return p->get_last_error(s);
}

static ss_instance_t* __open(plugin_api* p, ss_plugin_t* s, const char* o, ss_plugin_rc* r)
{
    return p->open(s, o, r);
}

static void __close(plugin_api* p, ss_plugin_t* s, ss_instance_t* h)
{
    p->close(s, h);
}

static const char* __list_open_params(plugin_api* p, ss_plugin_t* s, ss_plugin_rc* rc)
{
    return p->list_open_params(s, rc);
}

static const char* __get_progress(plugin_api* p, ss_plugin_t* s, ss_instance_t* h, uint32_t* r)
{
    return p->get_progress(s, h, r);
}

static const char* __event_to_string(plugin_api* p, ss_plugin_t *s, const ss_plugin_event *e)
{
    return p->event_to_string(s, e);
}

static ss_plugin_rc __next_batch(plugin_api* p, ss_plugin_t* s, ss_instance_t* h, uint32_t *n, ss_plugin_event **e)
{
    return p->next_batch(s, h, n, e);
}

static ss_plugin_rc __extract_fields(plugin_api* p, ss_plugin_t *s, const ss_plugin_event *e, uint32_t n, ss_plugin_extract_field *f)
{
    return p->extract_fields(s, e, n, f);
}

*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/xeipuuv/gojsonschema"
)

var (
	errNotInitialized = errors.New("plugin is not initialized")
	errNoSourcingCap  = errors.New("plugin does not support event sourcing capability")
)

type Plugin struct {
	m          sync.Mutex
	handle     *C.plugin_handle_t
	state      *C.ss_plugin_t
	caps       C.plugin_caps_t
	info       plugins.Info
	initSchema *sdk.SchemaInfo
	fields     []sdk.FieldEntry
	validated  bool
	validErr   error
}

func LoadAndValidate(path string) (*Plugin, error) {
	p, err := Load(path)
	if err != nil {
		return nil, err
	}
	err = p.Validate()
	if err != nil {
		p.Unload()
		return nil, err
	}
	return p, nil
}

func Load(path string) (*Plugin, error) {
	// load library
	errBuf := (*C.char)(C.malloc(C.uint64_t(C.__plugin_max_errlen) * C.sizeof_char))
	defer C.free(unsafe.Pointer(errBuf))
	p := &Plugin{}
	p.handle = C.plugin_load(C.CString(path), errBuf)
	if p.handle == nil {
		return nil, errors.New(C.GoString(errBuf))
	}

	// get supported capabilities
	p.caps = C.plugin_get_capabilities(p.handle)

	// read static info (if available)
	p.info = plugins.Info{
		Version:             C.GoString(C.__get_info_str(p.handle.api.get_version)),
		RequiredAPIVersion:  C.GoString(C.__get_info_str(p.handle.api.get_required_api_version)),
		Name:                C.GoString(C.__get_info_str(p.handle.api.get_name)),
		Description:         C.GoString(C.__get_info_str(p.handle.api.get_description)),
		EventSource:         C.GoString(C.__get_info_str(p.handle.api.anon0.get_event_source)),
		Contact:             C.GoString(C.__get_info_str(p.handle.api.get_contact)),
		ID:                  uint32(C.__get_info_u32(p.handle.api.anon0.get_id)),
		ExtractEventSources: []string{},
	}
	if p.handle.api.get_init_schema != nil {
		t := (C.ss_plugin_schema_type)(C.SS_PLUGIN_SCHEMA_NONE)
		s := C.GoString(C.__get_init_schema(&p.handle.api, &t))
		// todo(jasondellaluce): update this once we support more schema types
		if t == (C.ss_plugin_schema_type)(C.SS_PLUGIN_SCHEMA_JSON) {
			p.initSchema = &sdk.SchemaInfo{Schema: s}
		}
	}

	// get static info related to extraction capability (if available)
	if p.HasCapExtraction() && p.handle.api.anon1.get_extract_event_sources != nil {
		str := C.GoString(C.__get_info_str(p.handle.api.anon1.get_extract_event_sources))
		if err := json.Unmarshal(([]byte)(str), &p.info.ExtractEventSources); err != nil {
			// capability is considered not supported if data is corrupted
			p.caps ^= C.CAP_EXTRACTION
		}
	}
	if p.HasCapExtraction() {
		str := C.GoString(C.__get_info_str(p.handle.api.anon1.get_fields))
		if err := json.Unmarshal(([]byte)(str), &p.fields); err != nil {
			// capability is considered not supported if data is corrupted
			p.caps ^= C.CAP_EXTRACTION
		}
	}

	return p, nil
}

func (p *Plugin) Unload() {
	p.m.Lock()
	defer p.m.Unlock()
	if p.handle != nil {
		p.destroy()
		C.plugin_unload(p.handle)
		p.handle = nil
	}
}

func (p *Plugin) validate() error {
	if !p.validated {
		errBuf := (*C.char)(C.malloc(C.uint64_t(C.__plugin_max_errlen) * C.sizeof_char))
		defer C.free(unsafe.Pointer(errBuf))
		if !C.plugin_check_required_api_version(p.handle, errBuf) ||
			!C.plugin_check_required_symbols(p.handle, errBuf) {
			return errors.New(C.GoString(errBuf))
		}
		if p.caps == C.CAP_NONE {
			return errors.New("plugin supports no capability")
		}
		p.validated = true
	}
	return p.validErr
}

func (p *Plugin) Validate() error {
	p.m.Lock()
	defer p.m.Unlock()
	return p.validate()
}

func (p *Plugin) HasCapExtraction() bool {
	return p.caps&C.CAP_EXTRACTION != 0
}

func (p *Plugin) HasCapSourcing() bool {
	return p.caps&C.CAP_SOURCING != 0
}

func (p *Plugin) Info() *plugins.Info {
	return &p.info
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	return p.initSchema
}

func (p *Plugin) Fields() []sdk.FieldEntry {
	return p.fields
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	p.m.Lock()
	defer p.m.Unlock()
	if !p.HasCapSourcing() {
		return nil, errNoSourcingCap
	}
	if p.handle.api.anon0.list_open_params == nil {
		return nil, errors.New("plugin does not implement list_open_params")
	}
	if p.state == nil {
		return nil, errNotInitialized
	}

	errBuf := (*C.char)(C.malloc(C.uint64_t(C.__plugin_max_errlen) * C.sizeof_char))
	defer C.free(unsafe.Pointer(errBuf))
	rc := C.ss_plugin_rc(sdk.SSPluginSuccess)
	str := C.GoString((C.__list_open_params(&p.handle.api, unsafe.Pointer(p.state), (*C.ss_plugin_rc)(&rc))))
	if rc != C.ss_plugin_rc(sdk.SSPluginSuccess) {
		return nil, errors.New(C.GoString(errBuf))
	}

	var ret []sdk.OpenParam
	if len(str) > 0 {
		if err := json.Unmarshal(([]byte)(str), &ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (p *Plugin) Init(config string) error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.state != nil {
		return fmt.Errorf("plugin is already initialized")
	}
	err := p.validate()
	if err != nil {
		return fmt.Errorf("plugin is not valid: %s", err.Error())
	}

	config, err = p.validateInitConfig(config)
	if err != nil {
		return fmt.Errorf("invalid plugin config: %s", err.Error())
	}

	rc := C.ss_plugin_rc(sdk.SSPluginSuccess)
	p.state = (*C.ss_plugin_t)(C.__init(&p.handle.api, C.CString(config), (*C.ss_plugin_rc)(&rc)))
	if rc == C.ss_plugin_rc(sdk.SSPluginSuccess) {
		return nil
	}
	if p.state != nil {
		err := p.lastError()
		p.destroy()
		return err
	}
	return errors.New("unknown initialization error")
}

// only json schemas are supported for now
func (p *Plugin) validateInitConfig(config string) (string, error) {
	if p.initSchema != nil {
		if len(config) == 0 {
			config = "{}"
		}
		schema := gojsonschema.NewStringLoader(p.initSchema.Schema)
		document := gojsonschema.NewStringLoader(config)
		result, err := gojsonschema.Validate(schema, document)
		if err != nil {
			return "", err
		}
		if !result.Valid() {
			// return fist error
			return "", errors.New(result.Errors()[0].Description())
		}
	}
	return config, nil
}

func (p *Plugin) destroy() {
	if p.state != nil {
		C.__destroy(&p.handle.api, unsafe.Pointer(p.state))
		p.state = nil
	}
}

func (p *Plugin) lastError() error {
	if p.state != nil {
		str := C.GoString(C.__get_last_err(&p.handle.api, unsafe.Pointer(p.state)))
		if len(str) == 0 {
			return nil
		}
		return errors.New(str)
	}
	return errNotInitialized
}
