cmake_minimum_required(VERSION 3.19)

set(PICO_SDK_PATH "../lib/pico-sdk" CACHE PATH "Path to pico-sdk")
set(PICO_BOARD pico_w CACHE STRING "Target board")

include(${PICO_SDK_PATH}/pico_sdk_init.cmake)
project(SST-Examples C CXX ASM)
pico_sdk_init()

# --- Auto-discover ARM GCC toolchain (arm-none-eabi-gcc) ---
# Try common locations (Homebrew, PATH) and set PICO_TOOLCHAIN_PATH if found.
if(NOT DEFINED PICO_TOOLCHAIN_PATH OR PICO_TOOLCHAIN_PATH STREQUAL "")
    find_program(ARM_NONE_EABI_GCC
        NAMES arm-none-eabi-gcc
        HINTS
            $ENV{PICO_TOOLCHAIN_PATH}/bin
            /opt/homebrew/opt/arm-none-eabi-gcc/bin
            /usr/local/opt/arm-none-eabi-gcc/bin
            /usr/local/bin
            /opt/homebrew/bin
    )
    if(ARM_NONE_EABI_GCC)
        get_filename_component(_ARM_BIN_DIR "${ARM_NONE_EABI_GCC}" DIRECTORY)
        get_filename_component(_ARM_PREFIX "${_ARM_BIN_DIR}/.." ABSOLUTE)
        set(PICO_TOOLCHAIN_PATH "${_ARM_PREFIX}" CACHE PATH "Auto-detected ARM GCC toolchain root" FORCE)
        message(STATUS "Auto-detected ARM GCC at: ${PICO_TOOLCHAIN_PATH}")
    else()
        message(WARNING "arm-none-eabi-gcc not found. Install it (e.g., 'brew install arm-none-eabi-gcc') or set PICO_TOOLCHAIN_PATH.")
    endif()
endif()

# --- Always use mbedTLS backend for embedded builds ---
set(USE_MBEDTLS ON CACHE BOOL "Force use of mbedTLS backend" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "Disable OpenSSL backend" FORCE)

# Include the main SST library (assuming the root directory is two levels up)
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

add_executable(embedded_client embedded_client.c)

# Include headers with #include "c_api.h"
target_include_directories(embedded_client PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../..)

# Link against the freshly built SST library and Pico Wi-Fi (lwIP+cyw43)
target_link_libraries(embedded_client 
    sst-c-api
    pico_stdlib
    pico_cyw43_arch_lwip_threadsafe_background
)

# Enable USB serial output (printf over USB)
pico_enable_stdio_usb(embedded_client 1)
# Disable UART serial output (no logs via TX/RX pins)
pico_enable_stdio_uart(embedded_client 0)

# Produce UF2, bin, map, etc.
pico_add_extra_outputs(embedded_client)