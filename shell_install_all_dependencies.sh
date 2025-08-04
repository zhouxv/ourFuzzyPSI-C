#! /bin/bash
set -e
source ./shell_utils.sh

# This script installs all necessary dependencies for the project.

install_libOTe(){
    rm -rf libOTe

    printf "################## Cloning libOTe repository   ###################\n\n"
    git clone https://github.com/osu-crypto/libOTe.git
    cd libOTe
    git checkout a403ec37c6a32148648b7d8fd66dc35318d9f99d

    # mkdir -p ./out && cp ../boost_1_86_0.tar.bz2 ./out/

    printf "################## Building libOTe             ###################\n\n"
    python3 build.py --all --boost --sodium

    printf "################## Installing libOTe           ###################\n\n"
    python3 build.py --install=../../out/install/
    cd ..
    
    rm -rf libOTe
}

install_pailliercryptolib(){
    rm -rf pailliercryptolib

    printf "################## Cloning paillier repository ###################\n\n"
    git clone https://github.com/intel/pailliercryptolib.git
    cd pailliercryptolib/
    git checkout 9858ecf67a4a3f1ce32b14ff6494e4a0cd7e0076
    
    printf "################## Building paillier           ###################\n\n"
    export IPCL_ROOT=$(pwd)
    cmake -S . -B build -DCMAKE_INSTALL_PREFIX=../../out/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF
    cmake --build build -j

    printf "################## Installing paillier         ###################\n\n"
    cmake --build build --target install -j
    cd ..

    rm -rf pailliercryptolib
}

install_blake3(){
    rm -rf BLAKE3

    printf "################## Cloning BLAKE3 repository   ###################\n\n"
    git clone https://github.com/BLAKE3-team/BLAKE3.git
    cd BLAKE3
    git checkout c7f0d216e6fc834b742456b39546c9835baa1277
    
    printf "################## Building BLAKE3             ###################\n\n"
    cmake -S c -B c/build -DCMAKE_INSTALL_PREFIX=../../out/install

    printf "################## Installing BLAKE3           ###################\n\n"
    cmake --build c/build --target install
    cd ..

    rm -rf BLAKE3
}

log "Installing all third party dependencies..."
mkdir -p thirdparty && cd thirdparty

install_libOTe
install_pailliercryptolib
install_blake3

rm -rf thirdparty

log "All dependencies installed successfully!"