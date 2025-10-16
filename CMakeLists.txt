# To debug, compile with:
# $ cmake -DCMAKE_BUILD_TYPE=Debug ../

cmake_minimum_required(VERSION 3.19)
project(sst-lib VERSION 1.0.0 LANGUAGES C)

# Crypto backend selection
option(USE_MBEDTLS "Use mbedTLS instead of OpenSSL" OFF)
option(USE_OPENSSL "Use OpenSSL (default)" ON)

# Set default to OpenSSL if neither is explicitly set
if(NOT USE_MBEDTLS AND NOT USE_OPENSSL)
    set(USE_OPENSSL ON)
endif()

# If USE_MBEDTLS is ON, turn off USE_OPENSSL
if(USE_MBEDTLS)
    set(USE_OPENSSL OFF)
endif()

# Ensure only one backend is selected
if(USE_MBEDTLS AND USE_OPENSSL)
    message(FATAL_ERROR "Cannot use both OpenSSL and mbedTLS. Please choose one.")
endif()

if(USE_MBEDTLS)
    message(STATUS "Using mbedTLS crypto backend")
    add_definitions(-DUSE_MBEDTLS)
elseif(USE_OPENSSL)
    message(STATUS "Using OpenSSL crypto backend")
endif()

# Only use host Threads on non-Pico builds
if(NOT DEFINED PICO_PLATFORM)
    find_package(Threads REQUIRED)
endif()

add_library(sst-c-api STATIC
  ${CMAKE_CURRENT_LIST_DIR}/c_api.c
  ${CMAKE_CURRENT_LIST_DIR}/c_common.c
  ${CMAKE_CURRENT_LIST_DIR}/c_crypto.c
  ${CMAKE_CURRENT_LIST_DIR}/c_secure_comm.c
  ${CMAKE_CURRENT_LIST_DIR}/load_config.c
  ${CMAKE_CURRENT_LIST_DIR}/ipfs.c)

# Add crypto backend source files
if(USE_OPENSSL)
    target_sources(sst-c-api PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/crypto_openssl.c)
elseif(USE_MBEDTLS)
    target_sources(sst-c-api PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/crypto_mbedtls.c)
endif()

if(USE_MBEDTLS)
    target_compile_definitions(sst-c-api PUBLIC USE_MBEDTLS)
elseif(USE_OPENSSL)
    target_compile_definitions(sst-c-api PUBLIC USE_OPENSSL)
endif()


set_target_properties(sst-c-api PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Add embedded mbedTLS if using mbedTLS
if(USE_MBEDTLS)
    target_sources(sst-c-api PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/embedded/src/sst_mbedtls.c)
    target_include_directories(sst-c-api PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/embedded/include
        ${CMAKE_CURRENT_LIST_DIR}/embedded/lib/mbedtls/include)

    # Build and link upstream mbedTLS as separate libraries (no file lists here)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/embedded/lib/mbedtls
                     ${CMAKE_CURRENT_BINARY_DIR}/mbedtls-build
                     EXCLUDE_FROM_ALL)

    # Link only what we use (crypto + x509). TLS layer is not required.
    target_link_libraries(sst-c-api PUBLIC mbedcrypto mbedx509)
    # Link host Threads only when not building for Pico SDK
    if(NOT DEFINED PICO_PLATFORM)
        target_link_libraries(sst-c-api PUBLIC Threads::Threads)
    endif()
elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(sst-c-api PUBLIC OpenSSL::Crypto OpenSSL::SSL)
    if(NOT DEFINED PICO_PLATFORM)
        target_link_libraries(sst-c-api PUBLIC Threads::Threads)
    endif()
endif()

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

# Install/export only when not vendoring mbedTLS
if(NOT USE_MBEDTLS)
  # Install the library and export target
  install(TARGETS sst-c-api
    EXPORT sst-libTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
  )

  include(CMakePackageConfigHelpers)

  install(
    EXPORT sst-libTargets
    FILE sst-libTargets.cmake
    NAMESPACE sst-lib::
    DESTINATION lib/cmake/sst-lib
  )

  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/sst-libConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sst-libConfig.cmake
    INSTALL_DESTINATION lib/cmake/sst-lib
  )
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/sst-libConfig.cmake
    DESTINATION lib/cmake/sst-lib
  )
endif()

# Install headers
install(FILES c_api.h DESTINATION include/sst-c-api)

# Build unit tests only for host builds (not Pico SDK)
if(NOT DEFINED PICO_PLATFORM)
  enable_testing()
  add_executable(crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/c_crypto_test.c)
  target_link_libraries(crypto_test PRIVATE sst-c-api)
  # Add mbedTLS include directories to test if using mbedTLS
  if(USE_MBEDTLS)
      target_include_directories(crypto_test PRIVATE
          ${CMAKE_CURRENT_LIST_DIR}/embedded/include
          ${CMAKE_CURRENT_LIST_DIR}/embedded/lib/mbedtls/include)
  endif()
  add_test(NAME crypto_test COMMAND crypto_test)
endif()