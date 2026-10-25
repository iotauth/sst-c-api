# SST C++ API.
#
# Builds the SST C++ library (crypto, sockets, logging, session API and
# IPFS helpers) and its unit tests.
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

option(SST_FETCH_SPDLOG "Fetch spdlog when no installed package is available" ON)
set(SST_SPDLOG_SOURCE_DIR "" CACHE PATH "Local spdlog source tree for offline builds")

if(NOT TARGET spdlog::spdlog)
  if(SST_SPDLOG_SOURCE_DIR)
    add_subdirectory("${SST_SPDLOG_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/spdlog"
                     EXCLUDE_FROM_ALL)
  else()
    find_package(spdlog CONFIG QUIET)
    if(NOT TARGET spdlog::spdlog)
      if(NOT SST_FETCH_SPDLOG)
        message(FATAL_ERROR
          "spdlog was not found. Set spdlog_DIR or SST_SPDLOG_SOURCE_DIR, "
          "or enable SST_FETCH_SPDLOG to download it.")
      endif()
      include(FetchContent)
      FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.17.0)
      FetchContent_MakeAvailable(spdlog)
    endif()
  endif()
endif()

find_package(OpenSSL REQUIRED)

# SST library and protocol messages.
add_library(${PROJECT_NAME} STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/crypto.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/net/sockets.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/log/log_manager.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/api.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/ipfs.cpp
  # Auth/entity messages, mirroring org.iot.auth.message in the Auth server.
  ${CMAKE_CURRENT_LIST_DIR}/src/message/iotsp_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/auth_hello_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/auth_alert_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/entity_req_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/session_key_req_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/add_reader_req_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/entity_resp_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/session_key_resp_message.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/message/add_reader_resp_message.cpp
  )

set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)

# The logging header exposes spdlog types to consumers.
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto spdlog::spdlog)

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
set_tests_properties(socket_test PROPERTIES TIMEOUT 10)

add_executable(api_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/api_test.cpp)
target_link_libraries(api_test PRIVATE ${PROJECT_NAME})
add_test(NAME api_test COMMAND api_test)

add_executable(message_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/message_test.cpp)
target_link_libraries(message_test PRIVATE ${PROJECT_NAME})
add_test(NAME message_test COMMAND message_test)

find_package(Threads REQUIRED)
add_executable(protocol_test tests/protocol_test.cpp)
target_link_libraries(protocol_test PRIVATE ${PROJECT_NAME} Threads::Threads)
add_test(NAME protocol_test COMMAND protocol_test)
set_tests_properties(protocol_test PROPERTIES TIMEOUT 30)

# Manual integration probe; requires a configured, running Auth server.
add_executable(auth_connect_test EXCLUDE_FROM_ALL auth_connect_test.cpp)
target_link_libraries(auth_connect_test PRIVATE ${PROJECT_NAME})
