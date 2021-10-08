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
#include "wrappers.h"

enum async_extractor_state
{
	INIT = 0,
	INPUT_READY = 1,
	PROCESSING = 2,
	DONE = 3,
	SHUTDOWN_REQ = 4,
	SHUTDOWN_DONE = 5,
};

static async_extractor_info *s_async_extractor_ctx = NULL;

static bool async_extractor_compare_exchange(async_extractor_info *ainfo,
					     enum async_extractor_state *expected_val,
					     enum async_extractor_state desired_val)
{
	bool weak = false;
	int success_memorder =  __ATOMIC_SEQ_CST;
	int failure_memorder =  __ATOMIC_SEQ_CST;
	return __atomic_compare_exchange_n(&ainfo->lock, expected_val, desired_val, weak, success_memorder, failure_memorder);
}

// Source: https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.5/html_node/Elapsed-Time.html
static int
timeval_subtract (result, x, y)
	struct timeval *result, *x, *y;
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

bool async_extractor_wait(async_extractor_info *ainfo)
{
	ainfo->lock = DONE;
	uint64_t ncycles = 0;
	bool sleeping = false;

	//
	// Worker has done and now waits for a new input or a shutdown request.
	// Note: we busy loop for the first 1ms to guarantee maximum performance.
	//       After 1ms we start sleeping to conserve CPU.
	//
	enum async_extractor_state old_val = INPUT_READY;

	struct timeval start_time;
	gettimeofday(&start_time, NULL);

	while(!async_extractor_compare_exchange(ainfo, &old_val, PROCESSING))
	{
		// shutdown
		if(old_val == SHUTDOWN_REQ)
		{
			ainfo->lock = SHUTDOWN_DONE;
			return false;
		}
		old_val = INPUT_READY;

		if(sleeping)
		{
			usleep(10000);
		}
		else
		{
			ncycles++;
			if(ncycles >= 100000)
			{
				struct timeval cur_time, delta_time;
				gettimeofday(&cur_time, NULL);
				timeval_subtract(&delta_time, &cur_time, &start_time);
				int delta_us = delta_time.tv_sec * 1000000 + delta_time.tv_usec;
				if(delta_us > 1000)
				{
					sleeping = true;
				}
				else
				{
					ncycles = 0;
				}
			}
		}
	}
	return true;
}

static void async_extractor_init(async_extractor_info *ainfo)
{
	ainfo->lock = INIT;
}

static void async_extractor_shutdown(async_extractor_info *ainfo)
{
	enum async_extractor_state old_val = DONE;
	while (async_extractor_compare_exchange(ainfo, &old_val, SHUTDOWN_REQ))
	{
		old_val = DONE;
	}

	// await shutdown
	// XXX/mstemm add a timeout to this
	while (ainfo->lock != SHUTDOWN_DONE);
}

static int32_t async_extractor_extract_field(async_extractor_info *ainfo,
					     const ss_plugin_event *evt,
					     ss_plugin_extract_field *field)
{
	ainfo->evt = evt;
	ainfo->field = field;

	enum async_extractor_state old_val = DONE;
	while (!async_extractor_compare_exchange(ainfo, &old_val, INPUT_READY))
	{
		old_val = DONE;
	}

	//
	// Once INPUT_READY state has been aquired, wait for worker completition
	//
	while(ainfo->lock != DONE);

	// rc now contains the error code for the extraction.
	return ainfo->rc;
}

// Call this function to use async field extraction. In
// plugin_destroy(), you *must* then call destroy_async_extractor.
async_extractor_info * create_async_extractor()
{
	s_async_extractor_ctx = (async_extractor_info *) malloc(sizeof(async_extractor_info));
	async_extractor_init(s_async_extractor_ctx);

	return s_async_extractor_ctx;
}

void destroy_async_extractor()
{
	async_extractor_shutdown(s_async_extractor_ctx);
	free(s_async_extractor_ctx);
	s_async_extractor_ctx = NULL;
}

// Defined in wrappers.go
extern int32_t plugin_extract_fields_sync(ss_plugin_t *s,
			      const ss_plugin_event *evt,
			      uint32_t num_fields,
				  ss_plugin_extract_field *fields);

// This is the plugin API function. If s_async_extractor_ctx is
// non-NULL, it calls the async extractor function. Otherwise, it
// calls the synchronous extractor function.
int32_t plugin_extract_fields(ss_plugin_t *s,
			      const ss_plugin_event *evt,
			      uint32_t num_fields,
			      ss_plugin_extract_field *fields)
{
	int32_t rc;

	if(s_async_extractor_ctx != NULL)
	{
		for(uint32_t i = 0; i < num_fields; i++)
		{
			rc = async_extractor_extract_field(s_async_extractor_ctx, evt, &fields[i]);

			if(rc != SS_PLUGIN_SUCCESS)
			{
				return rc;
			}
		}

		return SS_PLUGIN_SUCCESS;
	}

	return plugin_extract_fields_sync(s, evt, num_fields, fields);
}
