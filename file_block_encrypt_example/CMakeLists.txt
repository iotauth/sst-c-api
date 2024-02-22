cmake_minimum_required(VERSION 3.19)
project(SST VERSION 1.0.0 LANGUAGES C)

# Check `openssl version -d` and copy the path to OPENSSL_ROOT_DIR
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(OPENSSL_ROOT_DIR "/usr/local/ssl")
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(SSTLIB        
  ../c_api.c
  ../c_common.c
  ../c_crypto.c
  ../c_secure_comm.c
  ../load_config.c)

target_link_libraries(SSTLIB OpenSSL::SSL Threads::Threads)

add_executable(block_reader block_reader.c)
add_executable(block_writer block_writer.c)
add_executable(block_reader_load_s_key_list block_reader_load_s_key_list.c)

target_link_libraries(block_writer OpenSSL::SSL Threads::Threads SSTLIB)
target_link_libraries(block_reader OpenSSL::SSL Threads::Threads SSTLIB)
target_link_libraries(block_reader_load_s_key_list OpenSSL::SSL Threads::Threads SSTLIB)
