cmake_minimum_required(VERSION 3.10)

project(location_proof_example C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build SST C API from the repository root.
add_subdirectory(
    ../..
    ${CMAKE_CURRENT_BINARY_DIR}/sst-lib-build
)

# cJSON is used by verification_policy.c.
find_package(PkgConfig REQUIRED)
pkg_check_modules(CJSON REQUIRED IMPORTED_TARGET libcjson)

# ------------------------------------------------------------
# Prover
#
# The Prover:
#   1. Requests authorization.
#   2. Reads UWB ranging measurements.
#   3. Performs multilateration.
#   4. Sends its claimed position to the Resource.
# ------------------------------------------------------------

add_executable(
    prover
    prover.c
    protocol.c
    uwb_reader.c
    multilateration.c
)

target_link_libraries(
    prover
    sst-c-api
    m
)

# ------------------------------------------------------------
# Resource / Robot Arm
#
# The Resource:
#   1. Receives the Robot's claimed position.
#   2. Obtains a fresh UWB measurement.
#   3. Independently performs multilateration.
#   4. Compares claimed and verified positions.
#   5. Applies the Auth-provided verification policy.
# ------------------------------------------------------------

add_executable(
    robot_arm
    robot_arm.c
    protocol.c
    location_verifier.c
    verification_policy.c
    uwb_reader.c
    multilateration.c
)

target_link_libraries(
    robot_arm
    sst-c-api
    PkgConfig::CJSON
    m
)

# ------------------------------------------------------------
# Synthetic multilateration test
# ------------------------------------------------------------

add_executable(
    multilateration_test
    multilateration_test.c
    multilateration.c
)

target_link_libraries(
    multilateration_test
    m
)

# ------------------------------------------------------------
# UWB ranging / accuracy test
# ------------------------------------------------------------

add_executable(
    uwb_reader_test
    uwb_reader_test.c
    uwb_reader.c
    multilateration.c
)

target_link_libraries(
    uwb_reader_test
    m
)