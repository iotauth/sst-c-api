cmake_minimum_required(VERSION 3.10)

project(ipfs_examples_cpp)

# Add the main SST library
add_subdirectory(../../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(uploader uploader.cpp)
add_executable(downloader downloader.cpp)

foreach(prog uploader downloader)
    target_link_libraries(${prog} sst-c-api Threads::Threads)
endforeach()
