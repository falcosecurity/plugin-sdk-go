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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include "extract.h"

// Possibly oversimplified version of https://gcc.gnu.org/wiki/Visibility
#if defined _WIN32 || defined __CYGWIN__
#define FALCO_PLUGIN_SDK_PUBLIC __declspec(dllexport)
#else
#define FALCO_PLUGIN_SDK_PUBLIC
#endif

enum worker_state
{
	WAIT = 0,
	DATA_REQ = 1,
	EXIT_REQ = 2,
	EXIT_ACK = 3,
};

// todo: make this dynamic
static async_extractor_info* s_async_extractor_ctx[64] = { NULL };

async_extractor_info *async_init(ss_plugin_t *s)
{
	s_async_extractor_ctx[(uint32_t) s] = (async_extractor_info *)malloc(sizeof(async_extractor_info));
	return s_async_extractor_ctx[(uint32_t) s];
}

async_extractor_info *async_get(ss_plugin_t *s)
{
	return s_async_extractor_ctx[(uint32_t) s];
}

void async_deinit(ss_plugin_t *s)
{
	free(s_async_extractor_ctx[(uint32_t) s]);
	s_async_extractor_ctx[(uint32_t) s] = NULL;
}

// Defined in extract.go
extern int32_t plugin_extract_fields_sync(ss_plugin_t *s,
										  const ss_plugin_event *evt,
										  uint32_t num_fields,
										  ss_plugin_extract_field *fields);

static inline int32_t async_extract_request(ss_plugin_t *s,
											const ss_plugin_event *evt,
											uint32_t num_fields,
											ss_plugin_extract_field *fields)
{
	// Since no concurrent requests are supported,
	// we assume worker is already in WAIT state

	// Set input data
	s_async_extractor_ctx[(uint32_t) s]->s = s;
	s_async_extractor_ctx[(uint32_t) s]->evt = evt;
	s_async_extractor_ctx[(uint32_t) s]->num_fields = num_fields;
	s_async_extractor_ctx[(uint32_t) s]->fields = fields;

	// notify data request
	atomic_store_explicit(&s_async_extractor_ctx[(uint32_t) s]->lock, DATA_REQ, memory_order_seq_cst);

	// busy-wait until worker completation
	while (atomic_load_explicit(&s_async_extractor_ctx[(uint32_t) s]->lock, memory_order_seq_cst) != WAIT);

	return s_async_extractor_ctx[(uint32_t) s]->rc;
}

// This is the plugin API function. If s_async_extractor_ctx is
// non-NULL, it calls the async extractor function. Otherwise, it
// calls the synchronous extractor function.
FALCO_PLUGIN_SDK_PUBLIC int32_t plugin_extract_fields(ss_plugin_t *s,
							  const ss_plugin_event *evt,
							  uint32_t num_fields,
							  ss_plugin_extract_field *fields)
{
	if (s_async_extractor_ctx[(uint32_t) s] != NULL)
	{
		return async_extract_request(s, evt, num_fields, fields);
	}

	return plugin_extract_fields_sync(s, evt, num_fields, fields);
}
