cmake_minimum_required(VERSION 3.19)
project(SST-CPP-IPFS-Examples VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build the SST C++ library (also builds its unit tests).
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-cpp-lib-build)

find_package(Threads REQUIRED)

add_executable(entity_uploader entity_uploader.cpp)
add_executable(entity_downloader entity_downloader.cpp)
add_executable(secure_entity_uploader secure_entity_uploader.cpp)
add_executable(secure_entity_downloader secure_entity_downloader.cpp)

foreach(prog entity_uploader entity_downloader secure_entity_uploader
             secure_entity_downloader)
    target_link_libraries(${prog} sst-cpp-api Threads::Threads)
endforeach()
