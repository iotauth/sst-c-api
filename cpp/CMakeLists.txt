# SST C++ cryptography API.
#
# Builds the crypto library (cpp/src/crypto.{hpp,cpp}) and its unit test
# (cpp/tests/crypto_test.cpp).
#
# To build and run the tests:
#   cd cpp
#   cmake -S . -B build
#   cmake --build build
#   ctest --test-dir build --output-on-failure

cmake_minimum_required(VERSION 3.19)
project(sst-cpp-api VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# Crypto library.
add_library(sst-cpp-api STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/crypto.cpp)

set_target_properties(sst-cpp-api PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(sst-cpp-api PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)

target_link_libraries(sst-cpp-api PUBLIC OpenSSL::Crypto OpenSSL::SSL)

# Compiler warnings.
if(MSVC)
  target_compile_options(sst-cpp-api PRIVATE /W4 /WX)
else()
  target_compile_options(sst-cpp-api PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Unit tests.
enable_testing()

add_executable(crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE sst-cpp-api)
add_test(NAME crypto_test COMMAND crypto_test)
