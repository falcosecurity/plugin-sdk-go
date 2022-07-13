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

// This enumerates the states of the shared lock between the C and the Go worlds.
// At a given time, there can be multiple C consumers requesting the extraction of
// 1+ fields, and one Go worker that synchronizes with the consumers through
// the shared lock, resolving one request per time.
enum worker_state
{
	// the worker is free and there is no on-going consumer request
	IDLE     = 0,
	// a request is accepted and the worker is waiting for the consumer to
	// confirm by sending the request type and its data
	WAIT     = 1,
	// the consumer sent a data request and the worker is resolving it
	REQ_DATA = 2,
	// the worker sent a response to a data request and the consumer is
	// evaluating it
	ACK_DATA = 3,
	// the consumer sent an exit request and the worker is resolving it
	REQ_EXIT = 4,
	// the worker sent a response to an exit request and the consumer is
	// evaluating it
	ACK_EXIT = 5,
};

static async_extractor_info *s_async_extractor_ctx = NULL;

async_extractor_info *async_init()
{
	s_async_extractor_ctx = (async_extractor_info *)malloc(sizeof(async_extractor_info));
	return s_async_extractor_ctx;
}

void async_deinit()
{
	free(s_async_extractor_ctx);
	s_async_extractor_ctx = NULL;
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
	// wait until worker accepts our request
	enum worker_state old_val = IDLE;
	while (!atomic_compare_exchange_weak_explicit(
			&s_async_extractor_ctx->lock,
			(int32_t *) &old_val,
			WAIT,
			memory_order_seq_cst,
			memory_order_relaxed))
    {
        old_val = IDLE;
    }

	// prepare input and send data request
	s_async_extractor_ctx->s = s;
	s_async_extractor_ctx->evt = evt;
	s_async_extractor_ctx->num_fields = num_fields;
	s_async_extractor_ctx->fields = fields;
	s_async_extractor_ctx->rc = SS_PLUGIN_FAILURE;
	atomic_store_explicit(&s_async_extractor_ctx->lock, REQ_DATA, memory_order_seq_cst);

	// busy-wait until worker completation
	while (atomic_load_explicit(&s_async_extractor_ctx->lock, memory_order_seq_cst) != ACK_DATA);

	// read result code and free-up the worker
	int32_t rc = s_async_extractor_ctx->rc;

	atomic_store_explicit(&s_async_extractor_ctx->lock, IDLE, memory_order_seq_cst);
	return rc;
}

// This is the plugin API function. If s_async_extractor_ctx is
// non-NULL, it calls the async extractor function. Otherwise, it
// calls the synchronous extractor function.
FALCO_PLUGIN_SDK_PUBLIC int32_t plugin_extract_fields(ss_plugin_t *s,
							  const ss_plugin_event *evt,
							  uint32_t num_fields,
							  ss_plugin_extract_field *fields)
{
	if (s_async_extractor_ctx != NULL)
	{
		return async_extract_request(s, evt, num_fields, fields);
	}

	return plugin_extract_fields_sync(s, evt, num_fields, fields);
}
