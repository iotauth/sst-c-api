cmake_minimum_required(VERSION 3.19)
project(SST-CPP-Server-Client-Examples VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build the SST C++ library (also builds its unit tests).
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-cpp-lib-build)

find_package(Threads REQUIRED)

add_executable(entity_client entity_client.cpp)
add_executable(entity_server entity_server.cpp)
add_executable(threaded_get_target_id_client threaded_get_target_id_client.cpp)
add_executable(threaded_get_target_id_server threaded_get_target_id_server.cpp)

# Link against the freshly built SST C++ library.
target_link_libraries(entity_client sst-cpp-api Threads::Threads)
target_link_libraries(entity_server sst-cpp-api Threads::Threads)
target_link_libraries(threaded_get_target_id_client sst-cpp-api Threads::Threads)
target_link_libraries(threaded_get_target_id_server sst-cpp-api Threads::Threads)
