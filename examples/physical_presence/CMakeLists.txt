cmake_minimum_required(VERSION 3.19)
project(SST-Physical-Presence-Example VERSION 1.0.0 LANGUAGES C)

# Include main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(robot robot.c)
add_executable(box box.c)

target_link_libraries(robot sst-c-api)
target_link_libraries(box sst-c-api)
