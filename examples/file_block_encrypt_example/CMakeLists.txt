cmake_minimum_required(VERSION 3.19)
project(SST-Examples VERSION 1.0.0 LANGUAGES C)

# Include the main SST library (assuming the root directory is two levels up)
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(block_reader block_reader.c)
add_executable(block_writer block_writer.c)
add_executable(block_reader_load_s_key_list block_reader_load_s_key_list.c)

target_link_libraries(block_writer sst-c-api)
target_link_libraries(block_reader sst-c-api)
target_link_libraries(block_reader_load_s_key_list sst-c-api)
