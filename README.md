# FuzzyPSI Benchmark Scripts

This document provides usage instructions for the benchmark scripts accompanying our FuzzyPSI (Fuzzy Private Set Intersection) implementation from the paper ["Efficient Fuzzy PSI Based on Prefix Representation"](https://dl.acm.org/doi/10.1145/3719027.3765203).
These scripts are designed to evaluate protocol performance across different parameter configurations, including varying set sizes, dimensions, metrics, and radius thresholds. The three scripts correspond to different protocol types: **FMAP**, **low-dimensional FuzzyPSI**, and **high-dimensional FuzzyPSI**. Each script automates the execution of multiple protocol runs and outputs communication cost and runtime measurements.

## 1. Usage Guide for `./build/main`

This section describes the usage of the executable file located at `./build/main`.

### Command Flags

| Flag  |         Meaning          | Optional Values                                              |
| :---: | :----------------------: | ------------------------------------------------------------ |
|   p   |      Protocol type       | `3`: Low-dimensional protocol<br/>`4`: High-dimensional protocol<br/>`5`: FMAP protocol |
|   d   |        Dimension         | `2`, `6`, `10`                                               |
|   m   |          Metric          | `0`: L<sub>∞</sub><br/>`1`: L<sub>1</sub><br/>`2`: L<sub>2</sub> |
| delta |          Radius          | `10`, `60`, `250`                                            |
|   n   |      Input set size      | `8`, `12`, `16`                                              |
|  log  |        Log level         | `0`: off<br/>`1`: info<br/>`2`: debug                        |
| trait | Batch test configuration | `3`                                                          |

## 2. Benchmark Scripts

Three benchmark scripts are provided to evaluate different protocol configurations. Each script runs the `./build/main` executable with specific parameter sweeps and fixed configurations.

| Script                         | Protocol Type             | Description                                                  |
| ------------------------------ | ------------------------- | ------------------------------------------------------------ |
| `shell_run_bench_fmap.sh`      | FMAP             | Evaluates FMAP protocol across different dimensions and set sizes |
| `shell_run_bench_fpsi_low.sh`  | Low-dimensional  | Evaluates low-dimensional FuzzyPSI across different metrics  |
| `shell_run_bench_fpsi_high.sh` | High-dimensional | Evaluates high-dimensional FuzzyPSI with fixed dimension     |

### 2.1 `shell_run_bench_fmap.sh`

This script benchmarks the FMAP protocol. It varies the set size `-n` (8, 12, 16), dimension `-d` (2, 6, 10), and radius `-delta` (10, 60, 250).

**Run:**

```bash
./shell_run_bench_fmap.sh
```

### 2.2 `shell_run_bench_fpsi_low.sh`

This script benchmarks the low-dimensional FuzzyPSI protocol. It varies the set size `-n` (8, 12, 16), metric `-m` (0, 1, 2), and radius `-delta` (10, 60, 250), with fixed dimension `-d 2`.

**Run:**

```bash
./shell_run_bench_fpsi_low.sh
```

### 2.3 `shell_run_bench_fpsi_high.sh`

This script benchmarks the high-dimensional FuzzyPSI protocol. It varies the set size `-n` (8, 12, 16), dimension `-d` (6, 10, 15), radius `-delta` (10, 60, 250), and metric `-m` (0, 1, 2).

**Run:**

```bash
./shell_run_bench_fpsi_high.sh
```
