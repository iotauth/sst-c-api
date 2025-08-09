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
include_directories(/home/josef/pico-sdk/src/rp2_common/hardware_irq/include)
include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(lifi_flash
    src/lifi_flash.c
)

target_link_libraries(lifi_flash PRIVATE
    pico_stdlib
    pico_rand
    pico_platform
    sst_embedded
    ram_handler
)

pico_enable_stdio_usb(lifi_flash 1)
pico_enable_stdio_uart(lifi_flash 0)
pico_add_extra_outputs(lifi_flash)
