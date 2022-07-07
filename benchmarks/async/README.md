# Async Extraction Benchmark

This little program is a benchmarking tool to measure the performance of the async extraction optimization (see: [pkg/sdk/symbols/extract](https://github.com/falcosecurity/plugin-sdk-go/tree/main/pkg/sdk/symbols/extract)).

### Usage

```
Usage: bench [options]
Options:
 -h, --help    Print this usage snippet.
 -a, --async   Run the benchmark by enabling the async extraction optimization (default: off).
 -n <number>   The number of extraction requests performed in the benchmark (default: 10000).
 -p <number>   The number of plugins that run the benchmark in parallel (default: 1).
```

### Example
```
> ./build/bench -n 100000 -a
plugin 1: 251.21 ns/extraction (elapsed time 25121098ns, extractions 100000)
```

### Description

The benchmark is implemented in C language, whereas the extraction function is implemented in Go by using the Plugin SDK Go. This is achieved by implementing a mock plugin using the SDK, then building it in `c-archive` mode, and then linking the resulting binary with the C code. The end result is a C executable that is able to call the symbols of the C plugin API, such as `plugin_init` and `plugin_extract_fields` (which are the ones we need to perform the benchmark in this case).

The goal here is to have a real use case estimation of how costly the C -> Go function calls are when the async worker optimization is enabled or disabled. This can't be achieved with the Go benchmarking tools, because the way the Go runtime behaves when built as `c-archive` and `c-shared` might influence the performance results. You can find a Go benchmark for this in https://github.com/falcosecurity/plugin-sdk-go/tree/main/pkg/sdk/symbols/extract/internal/asyncbench.

**NOTE**: this allows running multiple benchmarks in parallel by using the same shared Go code. This is unsafe with the current async extraction implementation, because it assumes a single-caller-single-worker execution model. However, this feature might become useful in the future one we support parallelized plugin code execution (see point **(B3)** of https://github.com/falcosecurity/falco/issues/2074).