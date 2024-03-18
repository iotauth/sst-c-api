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

add_executable(entity_client entity_client.c)
add_executable(entity_server entity_server.c)
add_executable(threaded_get_target_id_client threaded_get_target_id_client.c)
add_executable(threaded_get_target_id_server threaded_get_target_id_server.c)


target_link_libraries(entity_client SSTLIB)
target_link_libraries(entity_server SSTLIB)
target_link_libraries(threaded_get_target_id_client SSTLIB)
target_link_libraries(threaded_get_target_id_server SSTLIB)