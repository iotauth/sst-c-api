# C++ library build file for sst-lib

cmake_minimum_required(VERSION 3.19)
project(sst-lib-cpp VERSION 1.0.0 LANGUAGES CXX)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(sst-c-api-cpp STATIC
  ${CMAKE_CURRENT_LIST_DIR}/c_api.cpp
  ${CMAKE_CURRENT_LIST_DIR}/c_common.cpp
  ${CMAKE_CURRENT_LIST_DIR}/c_crypto.cpp
  ${CMAKE_CURRENT_LIST_DIR}/c_secure_comm.cpp
  ${CMAKE_CURRENT_LIST_DIR}/load_config.cpp
)

set_target_properties(sst-c-api-cpp PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Statically link OpenSSL into sst-c-api-cpp
target_link_libraries(sst-c-api-cpp PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

target_include_directories(sst-c-api-cpp PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Compiler flags
if(MSVC)
  target_compile_options(sst-c-api-cpp PRIVATE /W4 /WX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
# Exclude errors, because some can use GNU-specific variadic arguments. This is done for only compiling the SST library.
else()
  target_compile_options(sst-c-api-cpp PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Set DEBUG flag for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  message(STATUS "Enabling DEBUG flag")
  target_compile_definitions(sst-c-api-cpp PRIVATE DEBUG=1)
endif()

# Install the library
install(TARGETS sst-c-api-cpp
  EXPORT sst-lib-cppTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
)

# Export targets for find_package()
include(CMakePackageConfigHelpers)

install(
  EXPORT sst-lib-cppTargets
  FILE sst-lib-cppTargets.cmake
  NAMESPACE sst-lib::
  DESTINATION lib/cmake/sst-lib
)

# Creates in /usr/local/lib/cmake/sst-lib/sst-libConfig.cmake
# Acts as the entry point for find_package(sst-lib)
# Defines where to look for sst-libTargets.cmake
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sst-libConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/sst-lib-cppConfig.cmake
  INSTALL_DESTINATION lib/cmake/sst-lib
)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/sst-lib-cppConfig.cmake
  DESTINATION lib/cmake/sst-lib
)