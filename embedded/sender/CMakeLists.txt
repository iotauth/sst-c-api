cmake_minimum_required(VERSION 3.13)
project(sender_project C CXX ASM)

# Set PICO_SDK_PATH if not already set
if(NOT DEFINED PICO_SDK_PATH)
  set(PICO_SDK_PATH "$ENV{HOME}/pico-sdk" CACHE PATH "Path to the Pico SDK")
endif()

# Skip toolchain test (recommended for multi-target builds)
set(PICO_SKIP_TOOLCHAIN_TEST 1)

# Import Pico SDK
include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
pico_sdk_init()

# === Executable: LiFi Sender with Embedded Encryption ===
add_executable(lifi_sender_embedded
    src/lifi_sender_embedded.c
)

target_link_libraries(lifi_sender_embedded PRIVATE
    pico_stdlib
    pico_rand
    sst_embedded
)

pico_enable_stdio_usb(lifi_sender_embedded 1)
pico_enable_stdio_uart(lifi_sender_embedded 0)
pico_add_extra_outputs(lifi_sender_embedded)
