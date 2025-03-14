cmake_minimum_required(VERSION 3.22)
project(ourFPSI)

include_directories(thirdparty/BLAKE3/c/)
include_directories(utils)
include_directories(fpsi)
include_directories(frontend)

file(GLOB_RECURSE SRCS
    frontend/*.cpp
    fpsi/*.cpp
    utils/*.cpp
)

add_executable(main ${SRCS})

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2 -fsanitize=address)
    target_link_options(main PUBLIC -fsanitize=address)
endif()

if(CMAKE_BUILD_TYPE MATCHES "Release")
    target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2)
endif()

set(CMAKE_BUILD_TYPE Release)

# ############################################
# Link  libOTe                   #
# ############################################
find_package(libOTe REQUIRED HINTS "${CMAKE_SOURCE_DIR}/thirdparty/libOTe")

target_link_libraries(main oc::libOTe)

# ############################################
# Link  Myblake3                 #
# ############################################
target_link_libraries(main ${CMAKE_SOURCE_DIR}/thirdparty/BLAKE3/c/libblake3.so)

# ############################################
# Link  IPCL                     #
# ############################################
set(IPCL_DIR "${CMAKE_SOURCE_DIR}/out/install/lib/cmake/ipcl-2.0.0/")

find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main IPCL::ipcl)

# ############################################
# Link  GMP                      #
# ############################################
target_link_libraries(main /lib/x86_64-linux-gnu/libgmpxx.a /lib/x86_64-linux-gnu/libgmp.a)
