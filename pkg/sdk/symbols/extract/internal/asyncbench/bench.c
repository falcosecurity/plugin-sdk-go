// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include "bench.h"

void data_request(atomic_int_least32_t *lock)
{
    // We assume state_wait because no concurrent requests are supported
    enum worker_state old_val = WAIT;
    while (!atomic_compare_exchange_strong_explicit(lock, (uint32_t *)&old_val, DATA_REQ, memory_order_seq_cst, memory_order_seq_cst))
    {
        old_val = WAIT;
    }

    // state_data_req acquired, wait for worker completation
    while (atomic_load_explicit(lock, memory_order_seq_cst) != WAIT);
}

void async_benchmark(int32_t *lock, int n)
{
    for (int i = 0; i < n; i++)
    {
        data_request((atomic_int_least32_t *)lock);
    }
}

// Defined in async.go
extern int doWork(int);

int sync_benchmark(int n, int input)
{
    int output;
    for (int i = 0; i < n; i++)
    {
        output = doWork(input);
    }
    return output;
}

int do_work_c(int i)
{
    return i + 1;
}
