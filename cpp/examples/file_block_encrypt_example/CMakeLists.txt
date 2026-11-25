cmake_minimum_required(VERSION 3.19)
project(SST-CPP-Block-Examples VERSION 1.0.0 LANGUAGES CXX)

# Build the SST C++ library (also builds its unit tests).
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-cpp-lib-build)

add_executable(block_writer block_writer.cpp)
add_executable(block_reader block_reader.cpp)

target_link_libraries(block_writer sst-cpp-api)
target_link_libraries(block_reader sst-cpp-api)
