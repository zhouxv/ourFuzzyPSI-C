
# Efficient Fuzzy PSI Based on Prefix Representation

## 1. Introduction

Fuzzy PSI is a variant of PSI, which on input a set of points from the receiver and sender respectively, allows the receiver to learn which of the sender’s points lie within a threshold distance 𝛿 under a specific distance metric.

This work explores the use of ***prefix techniques*** to significantly improve the efficiency of fuzzy PSI protocols. By integrating spatial hashing, we develop efficient fuzzy PSI protocols for ***low-dimensional*** spaces. For ***high-dimensional*** settings, we present the first fuzzy PSI protocols achieving communication and computation complexity that scales logarithmically in 𝛿 and linearly in dimension 𝑑 and input set sizes.

## 2. Project Structure

The following is the structure description of this project. We have provided some scripts to assist with building and running tests. Please grant execute permissions to these scripts, all of which are designed to be run from the project root directory.

```
ourFuzzyPSI-C/
├─ frontend/                          # Front-end interface, program entry point
├─ fpsi/                              # Core FPSI protocol code, 
├────  fpsi_protocol.*       ## Implements core Fuzzy PSI workflow with testing for low/high-dimensional scenarios
├────  fpsi_recv.*           ## Receiver side of FPSI-CA protocol (Low-dim: L∞ and Lp) - Fig.16-17, Appendix B
├────  fpsi_sender.*         ## Sender side of FPSI-CA protocol (Low-dim: L∞ and Lp) - Fig.16-17, Appendix B
├────  fpsi_sender_high.*    ## Sender side of Fuzzy PSI-CA protocol (High-dim: L∞ and Lp) - Fig.12-13
├────  fpsi_recv_high.*      ## Receiver side of Fuzzy PSI-CA protocol (High-dim: L∞ and Lp) - Fig.12-13
├────  config.h              ## Main type aliases, cryptographic parameters, and constants used in the protocol
├────  rb_okvs/              ## C++ implementation of the OKVS structure from [BPSY23](https://eprint.iacr.org/2023/903.pdf)
├────  pis_new/              ## Our implementation of Private index search protocol in figure 9
├────  utils/                ## Helper functions for our protocols, including Profix Optimization technology in chapter 8
├─ thirdparty/                        # Third-party dependencies
├─ build/                             # Build output directory
├─ README.md                          # Project documentation
├─ CMakeLists.txt                     # CMake build configuration file
├─ Dockerfile                         # Docker image build file
├─ shell_install_all_dependencies.sh  # Dependency installation script
├─ shell_build_img.sh                 # Docker image build script
├─ shell_build_cmd.sh                 # Local build script
├─ shell_run_bench.sh                 # Benchmark run script
├─ shell_run_img.sh                   # Docker image run script
├─ shell_utils.sh                     # Shell utility functions
```

## 3. Prerequisites

**Supported OS :** `Ubuntu 20.04+` meet all project runtime specifications.

**CPU :** Our project utilizes [pailliercryptolib](https://github.com/intel/pailliercryptolib.git) for homomorphic encryption. `Pailliercryptolib` is to be used on `AVX512IFMA` enabled systems, as listed below in Intel CPU codenames: *Intel Cannon Lake, Intel Ice Lake, Intel Sapphire Rapids*. But for better performance, it is recommended to use the library on Intel Xeon® scalable processors - Ice Lake-SP or Sapphire Rapids-SP Xeon CPUs while fully utilizing the features.

**Memory :** `100GB or above recommended`. Peak memory usage during image build ranges from 66GB to 80GB, which can cause out-of-memory issues on machines with less than 64 GB RAM. Please ensure sufficient memory is available before proceeding.

**Docker Version :** `Docker 28.3.3+`  (Earlier versions have not been validated).

**Compiler :** `GCC 13` is required to ensure full *C++20* support. Please verify your `GCC` version.

**Dependencies :** Must have dependencies include:

```bash
cmake > 3.22
git
python3
libgmp-dev
libspdlog-dev
libssl-dev
libmpfr-dev
libfmt-dev
libtool
nasm
```

## 4. Build and Run

### Docker Build and Run(Recommend!)

#### Step 1: Obtain Docker Image of our Protocol

*Option 1 : Build the image locally using our scripts.*

```bash
# build docker image and run the docker container with the necessary capabilities
./shell_build_img.sh && ./shell_run_img.sh
```

*Option 2 : Pull the latest image directly from Docker Hub public repository using the following command:*

```bash
docker pull blueobsidian/fpsi_artifact:latest
```

#### step 2: Run our Protocol

```bash
# in container workdir, run benchmarks stript
./shell_run_bench.sh
```

#### step 3: Run protocols in [[23]](https://eprint.iacr.org/2024/330.pdf) and [[7]](https://eprint.iacr.org/2024/1462.pdf)

We provide Docker images for the two baseline implementations [[23]](https://eprint.iacr.org/2024/330.pdf) and [[7]](https://eprint.iacr.org/2024/1462.pdf) compared in our paper.
Run the benchmark using the following command:

```bash
### for [23]
docker pull blueobsidian/vbp24_artifact:latest # pull docker image
docker run -it --name vbp24_artifact --cap-add=NET_ADMIN blueobsidian/vbp24_artifact:latest
./shell_run_bench.sh # in container workdir, run benchmarks stript

### for [7]
docker pull blueobsidian/gao_artifact:latest # pull docker image
docker run -it --name gao_artifact --cap-add=NET_ADMIN blueobsidian/gao_artifact:latest
./shell_run_bench.sh # in container workdir, run benchmarks stript
```

### Local Build and Run

#### Step 1: Installing Third-Party Dependencies

There are mandatory dependencies on [libOTe](https://github.com/osu-crypto/libOTe.git) (multiple cryptographic primitive), [pailliercryptolib](https://github.com/intel/pailliercryptolib.git) (homomorphic encryption) and [Blake3](https://github.com/BLAKE3-team/BLAKE3.git) (hash function).

Run the `shell_install_all_dependencies.sh` script for automated dependency compilation and installation.

<!-- Note: to accelerate the build process, please ensure ["boost_1_86_0.tar.bz2"](https://archives.boost.io/release/1.86.0/source/boost_1_86_0.tar.bz2) exists in the `./thirdparty` directory. -->

#### Step 2: Build the Executable File

Running `shell_build_cmd.sh` produces deployable artifacts `main` in folder `./build`.

#### Step 3: Run benchmarks

Running `shell_run_bench.sh` to reproduce the experimental results from Table 3 in our paper.

As illustrated in the figure below, the left portion contains *the reference data from Table 3 of our paper*, while the right portion exhibits typical output produced by the `shell_run_bench.sh` script.

More data may be generated by running the compiled executable `./build/main` with appropriate parameters.

![benchmarks](./benchmarks.png)

### Network Emulation with tcconfig

In our image, we use [tcconfig](!https://github.com/thombashi/tcconfig) to set up traffic control of network bandwidth/latency. Usage instructions are provided below.

```bash
tcset lo --rate 10Gbps --overwrite               # Set the local loopback interface bandwidth to 10Gbps
tcset lo --rate 1Gbps --delay 5ms --overwrite    # Set bandwidth to 1Gbps and add 5ms network delay
tcset lo --rate 100Mbps --delay 20ms --overwrite # Set bandwidth to 100Mbps and add 20ms network delay
tcshow lo                                        # Display current traffic control settings for the loopback interface
tcdel lo -a                                      # Remove all traffic control rules from the loopback interface
```

## 5. Usage Guide for `./build/main`

This section describes the usage of the executable file located at `./build/main`.

### Command Flags

| Flag | Meaning             | Optional Values                                |
|:----:|:-------------------:|----------------------------------------------|
| p    | Protocol Type       | `1`: Single-run low-dimensional protocol<br/>`2`: Single-run high-dimensional protocol<br/>`3`: Batch low-dimensional protocol<br/>`4`: Batch high-dimensional protocol |
| d    | Dimension           | Tested dimensions: `2`, `5`, `8`<br />default value 2 for low-dimensional protocol, 5 for high-dimensional protocol |
| m    | Metric              | `0`: L<sub>∞</sub>(default)<br />`1`: L<sub>1</sub><br />`2`: L<sub>2</sub> |
| delta| Radius              | Only for `16`(default), `32`, `64`, `128`, `256`       |
| n    | The logarithm of the input set size | Tested values: `4`, `8`(default), `12` (only supports balanced case) |
| log | log level | `0`: off, `1`: info(default), `2`: debug, `3`: error |
| trait | Batch test quantity configuration | 1 (default value) |

### Usage samples

```bash
# low dimension L_inf 
./main -p 3 -d 2 -m 0 -n 4 -delta 16 -i 2

# high dimension L_2
./main -p 4 -d 5 -m 2 -n 8 -delta 16 -i 4
```
