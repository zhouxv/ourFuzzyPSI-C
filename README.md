
## Environment

This code and following instructions are tested on Ubuntu 20.04, with `g++ 13.1.0, CMake 3.30.5, GNU Make 4.2.1`.

### Install dependencies

```bash
##############################
# install gmp
sudo apt install libgmp-dev

##############################
# install libOTe
git clone https://github.com/osu-crypto/libOTe.git
cd libOTe
python3 build.py --all --boost --sodium
python3 build.py --install=../out/install/
cd ..

##############################
# install pailliercryptolib
sudo apt-get install libtool
sudo apt-get install nasm
sudo apt-get install libssl-dev
git clone https://github.com/intel/pailliercryptolib.git
cd pailliercryptolib/
export IPCL_ROOT=$(pwd)
sudo cmake -S . -B build -DCMAKE_INSTALL_PREFIX=../out/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF
sudo cmake --build build -j
sudo cmake --build build --target install -j
cd ..

##############################
# build BLAKE3 x86 架构
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd ./BLAKE3/c
gcc -shared -O3 -o libblake3.so blake3.c blake3_dispatch.c blake3_portable.c \
    blake3_sse2_x86-64_unix.S blake3_sse41_x86-64_unix.S blake3_avx2_x86-64_unix.S \
    blake3_avx512_x86-64_unix.S
cd ../../

##############################
# build FPSI
mkdir -p ./out/build && cd ./out/build
cmake -DCMAKE_BUILD_TYPE=Debug ../..
cmake -DCMAKE_BUILD_TYPE=Release ../..
cmake ../..
make -j

./main -p -m 0 -d 2 -r 8 -s 8 -i 3 -delta 16
gdb --args ./main -p -m 0 -d 2 -r 4 -s 4 -i 3 -delta 16
valgrind ./main -p -m 0 -d 2 -r 8 -s 8 -i 3 -delta 16
```
