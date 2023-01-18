cmake_minimum_required(VERSION 3.19)
project(SST VERSION 1.0.0 LANGUAGES C)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(OPENSSL_ROOT_DIR /usr/local/include/openssl)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
  set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
endif()

find_package(OpenSSL REQUIRED)
if(_OPENSSL_FOUND is true)
    message(1)
endif()
find_package(Threads REQUIRED)
if(THREADS_FOUND is true)
    message(2)
endif()


add_executable(entity_client entity_client.c ../c_api.c ../c_common.c ../c_crypto.c ../c_secure_comm.c ../load_config.c)
add_executable(entity_server entity_server.c ../c_api.c ../c_common.c ../c_crypto.c ../c_secure_comm.c ../load_config.c)

target_link_libraries(entity_client OpenSSL::SSL)
target_link_libraries(entity_server OpenSSL::SSL)
target_link_libraries(entity_client Threads::Threads)
target_link_libraries(entity_server Threads::Threads)