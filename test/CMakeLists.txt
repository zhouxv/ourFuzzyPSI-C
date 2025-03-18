cmake_minimum_required(VERSION 3.22)

include_directories(../thirdparty/BLAKE3/c/)
include_directories(../utils)
include_directories(../fpsi)

file(GLOB_RECURSE SRCS
    ../fpsi/*.cpp
    ../utils/*.cpp
    test_all.cpp
)

add_executable(main ${SRCS})

target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2)

set(CMAKE_BUILD_TYPE Release)

# ############################################
# Link  libOTe                   #
# ############################################
find_package(libOTe REQUIRED HINTS "../thirdparty/libOTe")

target_link_libraries(main oc::libOTe)

# ############################################
# Link  Myblake3                 #
# ############################################
# 注意, find 最好

target_link_libraries(main "${CMAKE_SOURCE_DIR}/../thirdparty/BLAKE3/c/libblake3.so")

# ############################################
# Link  IPCL                     #
# ############################################
set(IPCL_DIR "../out/install/lib/cmake/ipcl-2.0.0/")

find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main IPCL::ipcl)

# ############################################
# Link  GMP                      #
# ############################################
target_link_libraries(main /lib/x86_64-linux-gnu/libgmpxx.a /lib/x86_64-linux-gnu/libgmp.a)
