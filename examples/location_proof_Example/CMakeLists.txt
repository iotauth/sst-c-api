cmake_minimum_required(VERSION 3.19)
project(SST-Examples VERSION 1.0.0 LANGUAGES C)

# Include the main SST library (assuming the root directory is two levels up)
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(entity_client entity_client.c)
add_executable(entity_server entity_server.c)
add_executable(threaded_get_target_id_client threaded_get_target_id_client.c)
add_executable(threaded_get_target_id_server threaded_get_target_id_server.c)

# Link against the freshly built SST library
target_link_libraries(entity_client sst-c-api)
target_link_libraries(entity_server sst-c-api)
target_link_libraries(threaded_get_target_id_client sst-c-api)
target_link_libraries(threaded_get_target_id_server sst-c-api)
