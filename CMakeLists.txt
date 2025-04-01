cmake_minimum_required(VERSION 3.22)
project(ourFPSI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/out/install")

# include_directories：用于指定头文件的搜索路径，而不是库文件的路径
include_directories(utils)
include_directories(fpsi)
include_directories(frontend)
include_directories(${CMAKE_SOURCE_DIR}/out/install/include)

file(GLOB_RECURSE SRCS
    frontend/*.cpp
    fpsi/*.cpp
)

add_executable(main ${SRCS})

target_compile_options(main PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++20> -lpthread -O2)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
set(CMAKE_BUILD_TYPE Release)

# ############################################
# Link  fmt                                  #
# ############################################
find_package(fmt REQUIRED)
target_link_libraries(main fmt::fmt)

# # ############################################
# # Link  libOTe                               #
# # ############################################
find_package(libOTe REQUIRED)

target_link_libraries(main oc::libOTe)

# # ############################################
# # Link  Myblake3                             #
# # ############################################
# # target_link_libraries：用于指定链接的库文件，但直接使用相对路径可能会导致问题
target_link_libraries(main ${CMAKE_SOURCE_DIR}/out/install/lib/libblake3.a)

# # ############################################
# # Link  IPCL                                 #
# # ############################################
find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main IPCL::ipcl)

# ############################################
# Link  GMP                                  #
# ############################################
target_link_libraries(main /lib/x86_64-linux-gnu/libgmpxx.a /lib/x86_64-linux-gnu/libgmp.a)
