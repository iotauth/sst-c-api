# To debug, compile with:
# $ cmake -DCMAKE_BUILD_TYPE=Debug ../

cmake_minimum_required(VERSION 3.19)
project(sst-lib VERSION 1.0.0 LANGUAGES C)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(sst-c-api STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/c_api.c
  ${CMAKE_CURRENT_LIST_DIR}/src/c_common.c
  ${CMAKE_CURRENT_LIST_DIR}/src/c_crypto.c
  ${CMAKE_CURRENT_LIST_DIR}/src/c_secure_comm.c
  ${CMAKE_CURRENT_LIST_DIR}/src/load_config.c
  ${CMAKE_CURRENT_LIST_DIR}/src/ipfs.c
  ${CMAKE_CURRENT_LIST_DIR}/physical_com/plan_json.c
  ${CMAKE_CURRENT_LIST_DIR}/physical_com/session_ctl.c
  ${CMAKE_CURRENT_LIST_DIR}/physical_com/hk.c
  ${CMAKE_CURRENT_LIST_DIR}/ultrasonic_com/ultrasonic_echo.c
  ${CMAKE_CURRENT_LIST_DIR}/ultrasonic_com/ultrasonic_echo_plan.c
  ${CMAKE_CURRENT_LIST_DIR}/physical_com/rssi_check.c
  ${CMAKE_CURRENT_LIST_DIR}/uwb_com/uwb_range.c)

set_target_properties(sst-c-api PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Statically link OpenSSL into sst-c-api
target_link_libraries(sst-c-api PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

target_include_directories(sst-c-api PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Compiler flags
if(MSVC)
  target_compile_options(sst-c-api PRIVATE /W4 /WX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
# Exclude errors, because some can use GNU-specific variadic arguments. This is done for only compiling the SST library.
else()
  target_compile_options(sst-c-api PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Set DEBUG flag for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  message(STATUS "Enabling DEBUG flag")
  target_compile_definitions(sst-c-api PRIVATE DEBUG=1)
endif()

# Install the library
# Installs in /usr/local/lib/cmake/sst-lib/sst-libTargets.cmake & sst-libTargets-noconfig.cmake
# Contains target definitions for sst-c-api
# Helps CMake know how to link against sst-c-api

# sst-libTargets-noconfig.cmake Acts as the entry point for find_package(sst-lib)
# Defines where to look for sst-libTargets.cmake
install(TARGETS sst-c-api
  EXPORT sst-libTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
)

# Export targets for find_package()
include(CMakePackageConfigHelpers)

install(
  EXPORT sst-libTargets
  FILE sst-libTargets.cmake
  NAMESPACE sst-lib::
  DESTINATION lib/cmake/sst-lib
)

# Creates in /usr/local/lib/cmake/sst-lib/sst-libConfig.cmake
# Acts as the entry point for find_package(sst-lib)
# Defines where to look for sst-libTargets.cmake
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/sst-libConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/sst-libConfig.cmake
  INSTALL_DESTINATION lib/cmake/sst-lib
)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/sst-libConfig.cmake
  DESTINATION lib/cmake/sst-lib
)

# Install headers
install(FILES src/c_api.h DESTINATION include/sst-c-api)

# Build unit tests
enable_testing()

add_executable(crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/c_crypto_test.c)
target_link_libraries(crypto_test PRIVATE sst-c-api)
add_test(NAME crypto_test COMMAND crypto_test)

add_executable(hk_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/hk_test.c)
target_link_libraries(hk_test PRIVATE sst-c-api)
target_compile_options(hk_test PRIVATE -UNDEBUG)
add_test(NAME hk_test COMMAND hk_test)

add_executable(ultrasonic_echo_test ${CMAKE_CURRENT_SOURCE_DIR}/ultrasonic_com/ultrasonic_echo_test.c)
target_link_libraries(ultrasonic_echo_test PRIVATE sst-c-api)
target_compile_options(ultrasonic_echo_test PRIVATE -UNDEBUG)
add_test(NAME ultrasonic_echo_test COMMAND ultrasonic_echo_test)

add_executable(rssi_check_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/rssi_check_test.c)
target_link_libraries(rssi_check_test PRIVATE sst-c-api)
target_compile_options(rssi_check_test PRIVATE -UNDEBUG)
add_test(NAME rssi_check_test COMMAND rssi_check_test)

add_executable(uwb_range_test ${CMAKE_CURRENT_SOURCE_DIR}/uwb_com/uwb_range_test.c)
target_link_libraries(uwb_range_test PRIVATE sst-c-api)
target_compile_options(uwb_range_test PRIVATE -UNDEBUG)
add_test(NAME uwb_range_test COMMAND uwb_range_test)
