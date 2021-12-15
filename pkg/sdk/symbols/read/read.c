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

#include "read.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Utils
#define MAX(x, y)   x > y ? x : y
#define MIN(x, y)   x < y ? x : y

// Size of the read buffer in bytes
#define MAX_BUF_SIZE    64 * 1024

// Max number of instance states supported
#define MAX_INSTANCES   32

// Definition of the state maintained for each plugin instance
typedef struct {
    uint8_t buf[MAX_BUF_SIZE];
    uint8_t* buf_ptr;
    uint32_t buf_size;
    ss_plugin_rc last_rc;
} read_instance_state_t;

// Note: this follows a similar state management strategy as the one
// we have in the SDK internal cgo.Handle. Each handle is a numeric
// token representing the state number. As such, we leverage this
// to maintain a state mapping inside the C-world that we use for the
// read buffering.
static read_instance_state_t g_states[MAX_INSTANCES] = {0};

// Declaring the Go internal implementation.
// The puspose of this C middleware is to call this function as less
// as possible by using buffering, so that we mitigate the C->Go call
// overhead that we have in CGO.
extern ss_plugin_rc _plugin_read_go(
        ss_plugin_t* s, 
        ss_instance_t* h, 
        uint8_t* buf, 
        uint32_t n, 
        uint32_t *nread);

ss_plugin_rc plugin_read(ss_plugin_t* s, ss_instance_t* h, uint8_t* out, uint32_t n, uint32_t *nread)
{
    uint32_t flush_size;

    // todo: this will break if we ever decide to change the SDK cgo.Handle impl
    read_instance_state_t* state = &g_states[(uint64_t) s];

    // Due to buffering, we want to preserve the result code coming from the last
    // read() call, so that we can return it once the buffer gets flushed. However,
    // this is pointless for the TIMEOUT case.
    state->last_rc = state->last_rc == SS_PLUGIN_TIMEOUT ? SS_PLUGIN_SUCCESS : state->last_rc;

    *nread = 0;
    while (n > 0)
    {
        // The buffer is empty, we need to refill it with a read() call.
        if (state->buf_size == 0)
        {
            // If we need to refill the buffer, but we encountered an error in the
            // in the previous read() call, it means that we can't proceed and we
            // must return that error.
            if (state->last_rc != SS_PLUGIN_SUCCESS)
            {
                break;
            }

            // Note: the buffer can be filled with less than MAX_BUF_SIZE bytes
            state->buf_size = 0;
            state->buf_ptr = &state->buf[0];
            state->last_rc = _plugin_read_go(s, h, state->buf_ptr, MAX_BUF_SIZE, &state->buf_size);
        }

        // Flush the contents of the buffer
        flush_size = MIN(state->buf_size, n);
        memcpy(out, state->buf_ptr, flush_size);
        *nread += flush_size;
        out += flush_size;
        n -= flush_size;
        state->buf_ptr += flush_size;
        state->buf_size -= flush_size;
    }

    // Since we use buffering, it may happen that we reach an EOF or a TIMEOUT
    // even though the current reading batch is fully satisfied.
    // As a contract, we expect the plugin to return the same result code at
    // future read() calls, so in this case we return a success.
    if (state->buf_size > 0 && (state->last_rc  == SS_PLUGIN_EOF || state->last_rc  == SS_PLUGIN_TIMEOUT))
    {
        state->last_rc = SS_PLUGIN_SUCCESS;
    }

    return state->last_rc;
}
