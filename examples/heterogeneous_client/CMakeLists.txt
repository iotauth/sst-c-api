cmake_minimum_required(VERSION 3.19)
project(SST-Heterogeneous-Client VERSION 1.0.0 LANGUAGES C)

add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(heterogeneous_c_client heterogeneous_c_client.c)
target_link_libraries(heterogeneous_c_client sst-c-api)
