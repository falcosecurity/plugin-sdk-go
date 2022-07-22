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
	UNUSED   = 0,
	WAIT     = 1,
	DATA_REQ = 2,
	EXIT_REQ = 3,
	EXIT_ACK = 4,
};

static async_extractor_info *s_async_ctx_batch = NULL;

async_extractor_info *async_init(size_t size)
{
	s_async_ctx_batch = (async_extractor_info *)malloc(sizeof(async_extractor_info) * size);
	return s_async_ctx_batch;
}

void async_deinit()
{
	free(s_async_ctx_batch);
	s_async_ctx_batch = NULL;
}

// Defined in extract.go
extern int32_t plugin_extract_fields_sync(ss_plugin_t *s,
										  const ss_plugin_event *evt,
										  uint32_t num_fields,
										  ss_plugin_extract_field *fields);

// This is the plugin API function. If s_async_ctx_batch is
// non-NULL, it calls the async extractor function. Otherwise, it
// calls the synchronous extractor function.
FALCO_PLUGIN_SDK_PUBLIC int32_t plugin_extract_fields(ss_plugin_t *s,
							  const ss_plugin_event *evt,
							  uint32_t num_fields,
							  ss_plugin_extract_field *fields)
{
	// note: concurrent requests are supported on the context batch, but each
	// slot with a different value of ss_plugin_t *s. As such, for each lock
	// we assume worker is already in WAIT state. This is possible because
	// ss_plugin_t *s is an integer number representing a cgo.Handle, and can
	// have values in the range of [1, cgo.MaxHandle]
	//
	// todo(jasondellaluce): this is dependent on the implementation of our
	// cgo.Handle to optimize performance, so change this if we ever change
	// how cgo.Handles are represented
	
	// if async optimization is not available, go with a simple C -> Go call
	if (s_async_ctx_batch == NULL
		|| atomic_load_explicit(&s_async_ctx_batch[(size_t)s - 1].lock, memory_order_seq_cst) != WAIT)
	{
		return plugin_extract_fields_sync(s, evt, num_fields, fields);
	}

	// Set input data
	s_async_ctx_batch[(size_t)s - 1].s = s;
	s_async_ctx_batch[(size_t)s - 1].evt = evt;
	s_async_ctx_batch[(size_t)s - 1].num_fields = num_fields;
	s_async_ctx_batch[(size_t)s - 1].fields = fields;

	// notify data request
	atomic_store_explicit(&s_async_ctx_batch[(size_t)s - 1].lock, DATA_REQ, memory_order_seq_cst);

	// busy-wait until worker completation
	while (atomic_load_explicit(&s_async_ctx_batch[(size_t)s - 1].lock, memory_order_seq_cst) != WAIT);

	return s_async_ctx_batch[(size_t)s - 1].rc;
}
