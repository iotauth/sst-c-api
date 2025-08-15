cmake_minimum_required(VERSION 3.13)
project(sender_project C CXX ASM)

# The Pico SDK and MBEDTLS_DIR are set by the top-level CMakeLists.txt.
# Don't import the SDK again here.

add_executable(lifi_flash 
  src/lifi_flash.c
)

# Make sure the app sees mbedTLS config (not the SDK default)
target_include_directories(lifi_flash PRIVATE
  ${CMAKE_SOURCE_DIR}            # for "config/mbedtls_config.h"
  ${MBEDTLS_DIR}/include
  ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(lifi_flash PRIVATE
  MBEDTLS_CONFIG_FILE="config/mbedtls_config.h"
)

target_link_libraries(lifi_flash PRIVATE
  pico_stdlib
  pico_rand
  pico_platform
  sst_embedded
  ram_handler
)

# stdio + binary artifacts
pico_enable_stdio_usb(lifi_flash 1)
pico_enable_stdio_uart(lifi_flash 0)
pico_add_extra_outputs(lifi_flash)
