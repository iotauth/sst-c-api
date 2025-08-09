cmake_minimum_required(VERSION 3.13)

# === Pico SDK Setup ===
if(DEFINED ENV{PICO_SDK_PATH})
  set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}" CACHE PATH "Path to the Pico SDK")
  set(PICO_SKIP_TOOLCHAIN_TEST 1)
  include(${PICO_SDK_PATH}/pico_sdk_init.cmake)
  set(HAS_PICO_SDK TRUE)
else()
  set(HAS_PICO_SDK FALSE)
endif()

project(sst_embedded_project C CXX ASM)

if(HAS_PICO_SDK)
  pico_sdk_init()
endif()

set(MBEDTLS_CONFIG_FILE "\"mbedtls_config.h\"")

# === mbedcrypto (minimal build) ===
add_library(mbedcrypto
  lib/mbedtls/library/aes.c
  lib/mbedtls/library/aesce.c
  lib/mbedtls/library/aria.c
  lib/mbedtls/library/camellia.c
  lib/mbedtls/library/ccm.c
  lib/mbedtls/library/chachapoly.c
  lib/mbedtls/library/chacha20.c
  lib/mbedtls/library/cipher.c
  lib/mbedtls/library/cipher_wrap.c
  lib/mbedtls/library/constant_time.c
  lib/mbedtls/library/des.c
  lib/mbedtls/library/gcm.c
  lib/mbedtls/library/nist_kw.c
  lib/mbedtls/library/platform.c
  lib/mbedtls/library/platform_util.c
  lib/mbedtls/library/poly1305.c
  lib/mbedtls/library/sha256.c
)

target_include_directories(mbedcrypto PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/include
  ${CMAKE_CURRENT_SOURCE_DIR}/config
)

target_include_directories(mbedcrypto PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include  # for sst_crypto_embedded.h and mbedtls_time_alt.h
)

target_compile_definitions(mbedcrypto PRIVATE
  MBEDTLS_NO_PLATFORM_ENTROPY
)

if(HAS_PICO_SDK)
  # Add Pico-specific source files for mbedcrypto
  target_sources(mbedcrypto PRIVATE src/mbedtls_time_alt.c)

  # Link the Pico standard library and other hardware libraries
  target_link_libraries(mbedcrypto PRIVATE pico_stdlib)

  # Define Pico-specific compile definitions
  target_compile_definitions(mbedcrypto PRIVATE
    MBEDTLS_PLATFORM_TIME_ALT
    MBEDTLS_PLATFORM_MS_TIME_ALT
  )
endif()

# === Platform-Specific RAM Handler ===
if(HAS_PICO_SDK)
    add_library(ram_handler
        src/pico_handler.c  # Pico-specific RAM handling
    )
    target_link_libraries(ram_handler PRIVATE pico_stdlib pico_rand pico_stdio_usb)
else()
    # NOTE: src/pi_handler.c does not exist in the file tree.
    # This will cause an error if building for a non-Pico target.
    add_library(ram_handler
        src/pi_handler.c  # Pi-specific RAM handling
    )
endif()

# === Embedded SST Crypto Wrapper ===
add_library(sst_embedded
  src/sst_crypto_embedded.c
  src/cmd_handler.c
)

# Only add config_handler.c if not using Pico SDK (Pi 4)
if(NOT HAS_PICO_SDK)
  target_sources(sst_embedded PRIVATE src/config_handler.c)
endif()

target_include_directories(sst_embedded PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/include
)

target_link_libraries(sst_embedded PUBLIC mbedcrypto)
target_link_libraries(sst_embedded PRIVATE ram_handler)


# === Add sender/receiver projects ===
if(HAS_PICO_SDK)
  add_subdirectory(sender)
else()
  add_subdirectory(receiver)
endif()