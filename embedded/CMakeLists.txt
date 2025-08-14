cmake_minimum_required(VERSION 3.13)

# --- Read .build_target (supports either BUILD_TARGET=... or TARGET=...) ---
set(BUILD_TARGET "")
set(_bt_file "${CMAKE_CURRENT_LIST_DIR}/.build_target")
if(EXISTS "${_bt_file}")
  file(STRINGS "${_bt_file}" _bt_lines)
  foreach(line IN LISTS _bt_lines)
    if(line MATCHES "^BUILD_TARGET=([^\r\n]*)")
      set(BUILD_TARGET "${CMAKE_MATCH_1}")
    elseif(line MATCHES "^TARGET=([^\r\n]*)")
      set(BUILD_TARGET "${CMAKE_MATCH_1}")
    endif()
  endforeach()
endif()

if(BUILD_TARGET STREQUAL "")
  message(FATAL_ERROR "No build target selected. Run: ./set_build pico | pi4")
endif()

# --- Lock Pico SDK to submodule ---
set(PICO_SDK_PATH "${CMAKE_CURRENT_LIST_DIR}/lib/pico-sdk"
    CACHE PATH "Path to the Pico SDK (fixed to submodule)" FORCE)

# Import Pico SDK *only* for Pico builds (before project())
if(BUILD_TARGET STREQUAL "pico")
  ## ------ AVOID DEFAULT CONFIGURE MESSAGES ---------- ##
  if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
  endif()
  set(PICO_COMPILER pico_arm_cortex_m0plus_gcc CACHE STRING "Pico toolchain")
  set(PICO_PLATFORM rp2040 CACHE STRING "Pico platform")
  set(PICO_BOARD    pico   CACHE STRING "Pico board")
  ## ------- END OF AVOID DEFAULT CONFIGURE ------ ##
  if(NOT EXISTS "${PICO_SDK_PATH}/external/pico_sdk_import.cmake")
    message(FATAL_ERROR "pico-sdk submodule missing at ${PICO_SDK_PATH}. Run: git submodule update --init --recursive")
  endif()
  include("${PICO_SDK_PATH}/external/pico_sdk_import.cmake")
endif()

project(sst_embedded LANGUAGES C CXX ASM)

# Initialize SDK & sanity (Pico only)
if(BUILD_TARGET STREQUAL "pico")
  set(PICO_SKIP_TOOLCHAIN_TEST 1)
  set(PICO_SDK_DISABLE_MBEDTLS 1)
  pico_sdk_init()

  find_program(ARM_GCC arm-none-eabi-gcc)
  if(NOT ARM_GCC)
    message(FATAL_ERROR "ARM GCC not found. Install: sudo apt install gcc-arm-none-eabi libnewlib-arm-none-eabi")
  endif()
endif()

message(STATUS "BUILD_TARGET=${BUILD_TARGET}")
message(STATUS "PICO_SDK_PATH=${PICO_SDK_PATH}")


# Choose a per-subproject binary dir under the target root
if(BUILD_TARGET STREQUAL "pico")
  set(_SUB_BIN "${CMAKE_BINARY_DIR}/sender")
  add_subdirectory(sender "${_SUB_BIN}")
elseif(BUILD_TARGET STREQUAL "pi4")
  set(_SUB_BIN "${CMAKE_BINARY_DIR}/receiver")
  add_subdirectory(receiver "${_SUB_BIN}")
else()
  message(FATAL_ERROR "Unknown BUILD_TARGET='${BUILD_TARGET}'")
endif()


# === mbedTLS (lock to submodule) ===
set(MBEDTLS_DIR "${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls"
    CACHE PATH "Path to vendored mbedTLS" FORCE)

if(NOT EXISTS "${MBEDTLS_DIR}/library/aes.c")
  message(FATAL_ERROR
    "mbedTLS submodule not found at:\n  ${MBEDTLS_DIR}\n"
    "\nRun: git submodule update --init --recursive")
endif()
message(STATUS "Using mbedTLS from: ${MBEDTLS_DIR}")

# === Sanity check the mbedTLS sources we require ===
foreach(f aes.c gcm.c sha256.c sha512.c cipher.c cipher_wrap.c platform.c platform_util.c ctr_drbg.c constant_time.c)
  if(NOT EXISTS ${MBEDTLS_DIR}/library/${f})
    message(FATAL_ERROR "Missing mbedTLS source: ${MBEDTLS_DIR}/library/${f}")
  endif()
endforeach()

# === mbedcrypto (lean AES+GCM+Cipher; add MD/Entropy) ===
add_library(mbedcrypto
  ${MBEDTLS_DIR}/library/aes.c
  ${MBEDTLS_DIR}/library/gcm.c
  ${MBEDTLS_DIR}/library/sha256.c
  ${MBEDTLS_DIR}/library/sha512.c
  ${MBEDTLS_DIR}/library/cipher.c
  ${MBEDTLS_DIR}/library/cipher_wrap.c
  ${MBEDTLS_DIR}/library/platform.c
  ${MBEDTLS_DIR}/library/platform_util.c
  ${MBEDTLS_DIR}/library/ctr_drbg.c
  ${MBEDTLS_DIR}/library/entropy.c
  ${MBEDTLS_DIR}/library/md.c
  ${MBEDTLS_DIR}/library/constant_time.c
)

# Put repo root and config first so it wins over the SDK defaults
target_include_directories(mbedcrypto
  PUBLIC
    ${CMAKE_SOURCE_DIR}          # <-- allows "config/mbedtls_config.h"
    ${MBEDTLS_DIR}/include
  PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# Force everyone (lib + dependents) to include config file explicitly
target_compile_definitions(mbedcrypto
  PUBLIC MBEDTLS_CONFIG_FILE="config/mbedtls_config.h"
)

# no Belt & suspenders lol: truly UNDEFINE unwanted SDK cipher modules for this lib
target_compile_options(mbedcrypto PRIVATE
  -UMBEDTLS_ARIA_C
  -UMBEDTLS_CAMELLIA_C
  -UMBEDTLS_DES_C
  -UMBEDTLS_NIST_KW_C
  -UMBEDTLS_CCM_C
  -UMBEDTLS_CHACHA20_C
  -UMBEDTLS_POLY1305_C
  -UMBEDTLS_CHACHAPOLY_C
)

# Pico-only: provide ms-time hook and stdlib linkage
if(BUILD_TARGET STREQUAL "pico")
  target_sources(mbedcrypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/mbedtls_time_alt.c)
  target_link_libraries(mbedcrypto PRIVATE pico_stdlib)
endif()

# === Platform-Specific RAM Handler ===
if(BUILD_TARGET STREQUAL "pico")
  add_library(ram_handler src/pico_handler.c src/cmd_handler.c)
  target_include_directories(ram_handler PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MBEDTLS_DIR}/include
  )
  target_link_libraries(ram_handler PRIVATE pico_stdlib pico_rand pico_stdio_usb mbedcrypto hardware_adc)
else()
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/pi_handler.c)
    add_library(ram_handler src/pi_handler.c)
  else()
    add_library(ram_handler INTERFACE)
  endif()
endif()

# === Embedded SST Crypto Wrapper === use for both pico and pi 4 builds
add_library(sst_embedded
  src/sst_crypto_embedded.c
)

target_include_directories(sst_embedded PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${MBEDTLS_DIR}/include
)

target_link_libraries(sst_embedded PUBLIC mbedcrypto)
if(BUILD_TARGET STREQUAL "pico")
  target_link_libraries(sst_embedded PRIVATE pico_stdlib)
endif()
target_link_libraries(sst_embedded PRIVATE ram_handler)
