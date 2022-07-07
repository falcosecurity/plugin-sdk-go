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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <threads.h>
#include <unistd.h>

#include "../../pkg/sdk/plugin_info.h"

#define SEC_TO_NS  1000000000L;

// defined and exported in bench.go
void plugin_destroy(ss_plugin_t *s);
ss_plugin_t* plugin_init(const char *config, ss_plugin_rc *rc);
ss_plugin_rc plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);

// benchmark options
int g_parallelism;
int g_niterations;
bool g_use_async;

void print_help()
{
}

void parse_options(int argc, char** argv)
{
    g_parallelism = 1;
    g_niterations = 10000;
    g_use_async = false;
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
        {
            print_help();
            exit(0);
        }
        else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--async") )
        {
            g_use_async = true;
        }
        else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "-n"))
        {
            int tmp;
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "option '%s' requires a parameter\n", argv[i - 1]);
                exit(1);
            }
            
            tmp = atoi(argv[i]);
            if (tmp <= 0)
            {
                fprintf(stderr, "option '%s' parameter must be a positive integer\n", argv[i - 1]);
                exit(1);
            }

            if (!strcmp(argv[i - 1], "-p"))
            {
                g_parallelism = tmp;
            }
            else
            {
                g_niterations = tmp;
            }
        }
        else
        {
            fprintf(stderr, "unrecognized option '%s'\n", argv[i]);
            print_help();
            exit(1);
        }
    }
}

int run_benchmark(void* plugin_ptr)
{
    ss_plugin_t* plugin = (ss_plugin_t*) plugin_ptr;
    ss_plugin_extract_field e;
    e.field_id = 0;
    e.field = "sample.field";
    e.arg_present = false;
    e.ftype = FTYPE_UINT64;
    e.flist = false;

    struct timespec start;
    if (clock_gettime(CLOCK_REALTIME, &start) == -1)
    {
      perror("clock gettime");
      return EXIT_FAILURE;
    }

    for (int i = 0; i < g_niterations; i++)
    {
        plugin_extract_fields(plugin, NULL, 1, &e);
    }

    struct timespec stop;
    if (clock_gettime(CLOCK_REALTIME, &stop) == -1)
    {
      perror("clock gettime");
      return EXIT_FAILURE;
    }

    int64_t time_ns = (int64_t)(stop.tv_nsec - start.tv_nsec) + (int64_t)(stop.tv_sec - start.tv_sec) * SEC_TO_NS;
    printf("plugin %ld: %.02f ns/extraction (elapsed time %ldns, extractions %d)\n",
        (uint64_t) plugin_ptr,
        (double) time_ns / (double) (g_niterations),
        time_ns,
        g_niterations);
    return 0;
}

int main(int argc, char** argv)
{
    parse_options(argc, argv);

    thrd_t* threads = (thrd_t*) malloc (sizeof(thrd_t) * g_parallelism);
    ss_plugin_t** plugins = (ss_plugin_t*) malloc (sizeof(ss_plugin_t*) * g_parallelism);

    for (int i = 0; i < g_parallelism; ++i)
    {
        ss_plugin_rc rc = SS_PLUGIN_SUCCESS;
        plugins[i] = plugin_init(g_use_async ? "async" : "", &rc);
        if (rc != SS_PLUGIN_SUCCESS)
        {
            fprintf(stderr, "can't initialize plugin");
            exit(1);
        }
        thrd_create(&threads[i], run_benchmark, (void*) plugins[i]);
    }

    for (int i = 0; i < g_parallelism; ++i)
    {
        thrd_join(threads[i], NULL);
        plugin_destroy(plugins[i]);
    }

    return 0;
}