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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <vector>
#include <string>

#include "../../pkg/sdk/plugin_api.h"

// defined in Go and exported from bench.go
extern "C"
{
    void plugin_destroy(ss_plugin_t*);
    ss_plugin_t* plugin_init(const ss_plugin_init_input *input, ss_plugin_rc *rc);
    ss_plugin_rc plugin_extract_fields(ss_plugin_t*, const ss_plugin_event_input*, const ss_plugin_field_extract_input*);
}

// global benchmark options
static int g_parallelism;
static int g_niterations;
static bool g_use_async;

static void print_help()
{
    printf(
        "Usage: bench [options]\n\n"
        "Options:\n"
        " -h, --help    Print this usage snippet.\n"
        " -a, --async   Run the benchmark by enabling the async extraction optimization (default: off).\n"
        " -n <number>   The number of extraction requests performed in the benchmark (default: 10000).\n"
        " -p <number>   The number of plugins that run the benchmark in parallel (default: 1).\n");
}

static void parse_options(int argc, char** argv)
{
    g_parallelism = 1;
    g_niterations = 10000;
    g_use_async = false;

    for (int i = 1; i < argc; i++)
    {
        auto arg = std::string(argv[i]);
        if (arg == "-h" || arg == "--help" )
        {
            print_help();
            exit(0);
        }
        else if (arg == "-a" || arg == "--async" )
        {
            g_use_async = true;
        }
        else if (arg == "-p" || arg == "-n")
        {
            int tmp;
            i++;
            if (i >= argc)
            {
                fprintf(stderr, "option '%s' requires a parameter\n", arg.c_str());
                exit(1);
            }
            
            tmp = atoi(argv[i]);
            if (tmp <= 0)
            {
                fprintf(stderr, "option '%s' parameter must be a positive integer\n", arg.c_str());
                exit(1);
            }

            if (arg == "-p")
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

static void benchmark(ss_plugin_t *plugin) noexcept
{
    // craft a mock extract request
    ss_plugin_extract_field e;
    e.field_id = 0;
    e.field = "sample.field";
    e.arg_present = false;
    e.ftype = FTYPE_UINT64;
    e.flist = false;
    ss_plugin_field_extract_input in;
    in.fields = &e;
    in.num_fields = 1;
    
    // request multiple extractions and compute total execution time
    auto start = std::chrono::high_resolution_clock::now();
    ss_plugin_rc rc = SS_PLUGIN_FAILURE;
    for (int i = 0; i < g_niterations; i++)
    {
        rc = plugin_extract_fields(plugin, NULL, &in);
        if (rc != SS_PLUGIN_SUCCESS)
        {
            fprintf(stderr, "plugin %" PRIu64 ": plugin_extract_fields failure: %d\n", (uint64_t) plugin, rc);
            return;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();

    // print stats summary
    auto time_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    printf("plugin %" PRIu64 ": %.02f ns/extraction (elapsed time %" PRIu64 "ns, extractions %d)\n",
        (uint64_t) plugin,
        (double) time_ns.count() / (double) (g_niterations),
        (uint64_t) time_ns.count(),
        g_niterations);
}

int main(int argc, char** argv)
{
    // parse user options
    parse_options(argc, argv);

    // initialize plugins and launch a benchmark for each of them in parallel
    std::vector<std::thread> threads;
    std::vector<ss_plugin_t*> plugins;
    for (int i = 0; i < g_parallelism; ++i)
    {
        ss_plugin_rc rc = SS_PLUGIN_FAILURE;
        ss_plugin_init_input in;
        in.config = g_use_async ? "async" : "";
        plugins.push_back(plugin_init(&in, &rc));
        if (rc != SS_PLUGIN_SUCCESS)
        {
            fprintf(stderr, "can't initialize plugin");
            exit(1);
        }
        threads.push_back(std::thread(benchmark, plugins[i]));
    }

    // wait for all banchmarks to finish and destroy plugins
    for (int i = 0; i < g_parallelism; ++i)
    {
        if (threads[i].joinable())
        {
            threads[i].join();
        }
        plugin_destroy(plugins[i]);
    }

    return 0;
}