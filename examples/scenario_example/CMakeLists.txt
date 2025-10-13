cmake_minimum_required(VERSION 3.10)

project(scenario_example)

# Add the main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp)
add_executable(syn_flood syn_flood.cpp)

foreach(prog server client syn_flood)
    target_link_libraries(${prog} sst-c-api Threads::Threads)
endforeach()
