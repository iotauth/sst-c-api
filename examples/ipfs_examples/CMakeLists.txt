cmake_minimum_required(VERSION 3.19)
project(SST-IPFS-Examples VERSION 1.0.0 LANGUAGES C)

# Add the main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

# List of executables
add_executable(entity_uploader entity_uploader.c ../../ipfs.c)
add_executable(entity_downloader entity_downloader.c ../../ipfs.c)
add_executable(secure_entity_uploader secure_entity_uploader.c ../../ipfs.c)
add_executable(secure_entity_downloader secure_entity_downloader.c ../../ipfs.c)

# Link against SST library and dependencies
foreach(prog entity_uploader entity_downloader secure_entity_uploader secure_entity_downloader)
    target_link_libraries(${prog} sst-c-api Threads::Threads)
endforeach()
