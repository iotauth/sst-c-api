cmake_minimum_required(VERSION 3.19)

# This part must come before project()
if(SST_PLATFORM_PICO)
  set(USE_MBEDTLS ON)
  set(USE_OPENSSL OFF)
  message(STATUS "Using mbedTLS crypto backend")
  if(NOT DEFINED PICO_SDK_PATH OR PICO_SDK_PATH STREQUAL "")
    set(PICO_SDK_PATH "${CMAKE_CURRENT_LIST_DIR}/../lib/pico-sdk" CACHE PATH "Path to pico-sdk")
  endif()
  set(PICO_BOARD pico2_w CACHE STRING "Target board" FORCE)
  include(${PICO_SDK_PATH}/pico_sdk_init.cmake)
endif()

project(sst-examples VERSION 1.0.0 LANGUAGES C CXX ASM)

# --- Always use mbedTLS backend for embedded builds ---
set(USE_MBEDTLS ON CACHE BOOL "Force use of mbedTLS backend" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "Disable OpenSSL backend" FORCE)
set(SST_PLATFORM_PICO ON CACHE BOOL "Build SST library for Raspberry Pi Pico targets" FORCE)

# Include the main SST library (assuming the root directory is two levels up)
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

add_executable(embedded_client embedded_client.c)

# Include headers with #include "c_api.h"
target_include_directories(embedded_client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../..)

set(FREERTOS_KERNEL_PATH "${CMAKE_CURRENT_LIST_DIR}/../lib/FreeRTOS-Kernel" CACHE PATH "Path to FreeRTOS Kernel" FORCE)
include(${FREERTOS_KERNEL_PATH}/portable/ThirdParty/GCC/RP2040/FreeRTOS_Kernel_import.cmake)
pico_sdk_init()
# Link against the freshly built SST library and Pico Wi-Fi (lwIP+cyw43)
target_link_libraries(embedded_client 
    sst-c-api
    pico_cyw43_arch_lwip_sys_freertos
    pico_stdlib
    pico_mbedtls
    FreeRTOS-Kernel-Heap4
)

  # Include lwipopts.h & mbedtls_sst_config.h & FreeRTOSConfig.h
  target_include_directories(embedded_client PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../include
  )

# Enable USB serial output (printf over USB)
pico_enable_stdio_usb(embedded_client 1)
# Disable UART serial output (no logs via TX/RX pins)
pico_enable_stdio_uart(embedded_client 0)


# Produce UF2, bin, map, etc.
pico_add_extra_outputs(embedded_client)
