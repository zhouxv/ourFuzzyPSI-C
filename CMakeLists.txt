cmake_minimum_required(VERSION 3.22)
project(ourFPSI)

# include_directories：用于指定头文件的搜索路径，而不是库文件的路径
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

target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2 -fsanitize=address -g)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

# target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2)
set(CMAKE_BUILD_TYPE Release)

# ############################################
# Link  libOTe                   #
# ############################################
find_package(libOTe REQUIRED HINTS "${CMAKE_SOURCE_DIR}/thirdparty/libOTe")

target_link_libraries(main oc::libOTe)

# ############################################
# Link  Myblake3                 #
# ############################################
# target_link_libraries：用于指定链接的库文件，但直接使用相对路径可能会导致问题
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
