
### Environment

This code and following instructions are tested on Ubuntu 20.04, with `g++ 13.1.0, CMake 3.30.5, GNU Make 4.2.1`.

## Build step by step

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
# build
mkdir -p ./out/build && cd ./out/build
cmake ../..
make -j
```
