cmake_minimum_required(VERSION 3.19)
project(SST-CPP-IPFS-Examples VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The SST C library provides the secure session API used by the server.
add_subdirectory(../../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

# spdlog is required by the SST C++ logging layer.
include(FetchContent)
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(spdlog)

# Compile the needed SST C++ API sources directly: adding cpp/CMakeLists.txt
# as a subdirectory here would clash with the C library's test target names.
add_executable(secure_ipfs_server
  secure_ipfs_server.cpp
  ../../src/net/sockets.cpp
  ../../src/log/log_manager.cpp)
target_include_directories(secure_ipfs_server PRIVATE ../../src)
target_link_libraries(secure_ipfs_server sst-c-api spdlog::spdlog
                      Threads::Threads)
