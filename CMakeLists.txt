# To debug, compile with:
# $ cmake -DCMAKE_BUILD_TYPE=Debug ../

cmake_minimum_required(VERSION 3.19)

project(sst-lib VERSION 1.0.0 LANGUAGES C CXX ASM)

# Crypto backend selection
# option(USE_MBEDTLS "Use mbedTLS instead of OpenSSL" OFF)
option(USE_OPENSSL "Use OpenSSL (default)" ON)

# Pico build off as default
option(SST_PLATFORM_PICO "Build SST library for Raspberry Pi Pico targets" OFF)

set(SST_CORE_SOURCES
  ${CMAKE_CURRENT_LIST_DIR}/c_api.c
  ${CMAKE_CURRENT_LIST_DIR}/c_common.c
  ${CMAKE_CURRENT_LIST_DIR}/c_crypto.c
  ${CMAKE_CURRENT_LIST_DIR}/c_secure_comm.c
  ${CMAKE_CURRENT_LIST_DIR}/load_config.c
)

add_library(sst-c-api STATIC ${SST_CORE_SOURCES})

# Add crypto backend source files
if(USE_OPENSSL)
  target_sources(sst-c-api PRIVATE 
    ${CMAKE_CURRENT_LIST_DIR}/crypto_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/ipfs.c)
  target_compile_definitions(sst-c-api PUBLIC USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(sst-c-api PUBLIC OpenSSL::Crypto OpenSSL::SSL)
  # list(APPEND SST_CORE_SOURCES ${CMAKE_CURRENT_LIST_DIR}/ipfs.c)
elseif(SST_PLATFORM_PICO)
  set(FREERTOS_KERNEL_PATH "${CMAKE_CURRENT_LIST_DIR}/embedded/lib/FreeRTOS-Kernel" CACHE PATH "Path to FreeRTOS Kernel" FORCE)
  include(${FREERTOS_KERNEL_PATH}/portable/ThirdParty/GCC/RP2040/FreeRTOS_Kernel_import.cmake)
  pico_sdk_init()
  target_link_libraries(sst-c-api PRIVATE 
    pico_cyw43_arch_lwip_sys_freertos
    pico_stdlib
    pico_mbedtls
    FreeRTOS-Kernel-Heap4
  )
  target_sources(sst-c-api PRIVATE ${CMAKE_CURRENT_LIST_DIR}/crypto_mbedtls.c)
  target_compile_definitions(sst-c-api PUBLIC USE_MBEDTLS)
  target_compile_definitions(sst-c-api PUBLIC SST_PLATFORM_PICO)
  # Include lwipopts.h & mbedtls_sst_config.h
  target_include_directories(sst-c-api PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/embedded/include
  )
endif()

target_include_directories(sst-c-api PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Compiler flags
if(MSVC)
  target_compile_options(sst-c-api PRIVATE /W4 /WX)
elseif(SST_PLATFORM_PICO)
  target_compile_options(sst-c-api PRIVATE -Wall -Wextra)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
# Exclude errors, because some can use GNU-specific variadic arguments. This is done for only compiling the SST library.
  target_compile_options(sst-c-api PRIVATE -Wall -Wextra)
else()
  target_compile_options(sst-c-api PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Set DEBUG flag for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  message(STATUS "Enabling DEBUG flag")
  target_compile_definitions(sst-c-api PRIVATE DEBUG=1)
endif()

# Install/export only when not vendoring mbedTLS
if(USE_OPENSSL)
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
if(USE_OPENSSL)
  enable_testing()
  add_executable(crypto_test ${CMAKE_CURRENT_SOURCE_DIR}/tests/c_crypto_test.c)
  target_link_libraries(crypto_test PRIVATE sst-c-api)
  add_test(NAME crypto_test COMMAND crypto_test)
endif()
