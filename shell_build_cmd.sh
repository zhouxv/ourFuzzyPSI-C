#! /bin/bash
set -e
source ./shell_utils.sh
# This script is used to build the project using CMake and Make.

mkdir -p build && cd build

log "Building the project with CMake and Make..."
docker_build_style "cmake .." "cmake .."
docker_build_style "make -j$(nproc)" "make -j$(nproc)"
log "Buidling completed successfully! You can find the built artifacts in the 'build' directory."