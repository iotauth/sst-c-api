cmake_minimum_required(VERSION 3.19)
project(SST_TEST LANGUAGES C)

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

add_executable(aes_test aes_test.c)

target_link_libraries(aes_test SSTLIB)

if(MSVC)
  target_compile_options(SSTLIB PRIVATE /W4 /WX)
else()
  target_compile_options(SSTLIB PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
