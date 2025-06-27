cmake_minimum_required(VERSION 3.10)

project(ipfs_examples_cpp)

add_executable(uploader uploader.cpp)
add_executable(downloader downloader.cpp)

target_include_directories(uploader PRIVATE ../../../.. /opt/homebrew/opt/openssl/include)
target_include_directories(downloader PRIVATE ../../../.. /opt/homebrew/opt/openssl/include)

target_link_directories(uploader PRIVATE /opt/homebrew/opt/openssl/lib ../../../build)
target_link_directories(downloader PRIVATE /opt/homebrew/opt/openssl/lib ../../../build)

target_link_libraries(uploader PRIVATE crypto sst-c-api)
target_link_libraries(downloader PRIVATE crypto sst-c-api)
