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


# Include spdlog
include(FetchContent)
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.17.0  # Replace with the desired tag or branch
)
FetchContent_MakeAvailable(spdlog)

set(INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
message(STATUS "SPDLOG INCLUDE PATH: ${CMAKE_CURRENT_SOURCE_DIR}/build/_deps/spdlog-src/include")
include_directories(
    ${INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/build/_deps/spdlog-src/include)


find_package(OpenSSL REQUIRED)

# Crypto library.
add_library(${PROJECT_NAME} STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/crypto.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/crypto.hpp
  ${CMAKE_CURRENT_LIST_DIR}/src/net/sockets.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/net/sockets.hpp
  ${CMAKE_CURRENT_LIST_DIR}/src/net/ssl_socket.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/net/ssl_socket.hpp
  ${CMAKE_CURRENT_LIST_DIR}/src/log/log_manager.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/log/log_manager.hpp
  ${CMAKE_CURRENT_LIST_DIR}/src/api.hpp
  ${CMAKE_CURRENT_LIST_DIR}/src/api.cpp
  )

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)

target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL)

target_link_libraries(${PROJECT_NAME} PRIVATE spdlog::spdlog)

# Compiler warnings.
if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
  target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Unit tests.
enable_testing()

add_executable(crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE ${PROJECT_NAME})
add_test(NAME crypto_test COMMAND crypto_test)

add_executable(socket_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/socket_test.cpp)
target_link_libraries(socket_test PRIVATE ${PROJECT_NAME})
add_test(NAME socket_test COMMAND socket_test)
