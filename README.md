
## Environment

This code and following instructions are tested on Ubuntu 20.04, with `g++ 13.1.0, CMake 3.30.5, GNU Make 4.2.1`.

### Install dependencies and build

```bash
##############################

sudo apt-get install libgmp-dev libspdlog-dev libtool nasm libssl-dev libmpfr-dev libfmt-dev

##############################
# install libOTe
mkdir thirdparty && cd thirdparty
git clone https://github.com/osu-crypto/libOTe.git
cd libOTe
python3 build.py --all --boost --sodium
python3 build.py --install=../../out/install/
cd ..

##############################
# install pailliercryptolib
git clone https://github.com/intel/pailliercryptolib.git
cd pailliercryptolib/
export IPCL_ROOT=$(pwd)
sudo cmake -S . -B build -DCMAKE_INSTALL_PREFIX=../../out/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF
sudo cmake --build build -j
sudo cmake --build build --target install -j
cd ..

##############################
# build BLAKE3 x86 架构
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd BLAKE3
cmake -S c -B c/build -DCMAKE_INSTALL_PREFIX=../../out/install
cmake --build c/build --target install
cd ..


##############################
# build FPSI
mkdir -p ./out/build && cd ./out/build
cmake -DCMAKE_BUILD_TYPE=Debug ../..
cmake -DCMAKE_BUILD_TYPE=Release ../..
cmake ../..
make -j
```

### Command to run the executable file
#### Command Flags
| Flag | Meaning             | Optional Values                                |
|:----:|:-------------------:|----------------------------------------------|
| p    | Protocol Type       | 1: Low-dimensional protocol<br>2: High-dimensional protocol |
| d    | Dimension           | Tested dimensions: 2, 5, 8                     |
| delta| Radius              | Only for 16, 32, 64, 128, 256                           |
| m    | Metric              | 0: L<sub>∞</sub><br>1: L<sub>1</sub><br>2: L<sub>2</sub>                |
| r    | Log Receiver Count  | Tested values: 4, 8, 12 (only supports balanced case) |
| s    | Log Sender Count    | Tested values: 4, 8, 12 (only supports balanced case) |
| i    | Size of intersection | Should not be greater than set_size |

#### Command samples
```bash
# low dimension L_inf
./main -p 1 -d 2 -m 0 -r 4 -s 4 -delta 16 -i 2

# high dimension L_2
./main -p 2 -d 5 -m 2 -r 4 -s 4 -delta 16 -i 4
```

#### Docker notes
need `tcconfig`, `iperf`
```bash
docker run  --privileged -dit ourfpsi:v0.0.1
tcset lo --rate 10Gbps --overwrite
tcset lo --rate 1Gbps --overwrite
tcset lo --rate 100Mbps --overwrite
tcset lo --rate 10Mbps --overwrite
tcshow lo
tcdel lo -a
```