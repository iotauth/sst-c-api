cmake_minimum_required(VERSION 3.19)
project(SST-Location-Proof VERSION 1.0.0 LANGUAGES C)

# Include the main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

# Prover executable
add_executable(
    prover
    prover.c
)

# Robot arm / resource executable
add_executable(
    robot_arm
    robot_arm.c
    location_verifier.c
)

# Link against SST
target_link_libraries(prover sst-c-api)
target_link_libraries(robot_arm sst-c-api)