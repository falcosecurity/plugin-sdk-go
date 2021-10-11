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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

typedef void ss_plugin_t;

// XXX/mstemm find a way to include plugin_info.h to avoid duplicating
// these types/values.

#define SS_PLUGIN_SUCCESS 0

typedef struct ss_plugin_event
{
	uint64_t evtnum;
	uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

typedef struct ss_plugin_extract_field
{
	const char *field;
	const char *arg;
	uint32_t ftype;

	bool field_present;
	char *res_str;
	uint64_t res_u64;
} ss_plugin_extract_field;

typedef struct async_extractor_info
{
	// Pointer as this allows swapping out events from other
	// structs.
	atomic_int lock;
	const ss_plugin_event *evt;
	ss_plugin_extract_field *field;
	int32_t rc;
} async_extractor_info;

async_extractor_info * create_async_extractor();
void destroy_async_extractor();
bool async_extractor_wait(async_extractor_info *ainfo);
