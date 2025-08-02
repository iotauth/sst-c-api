cmake_minimum_required(VERSION 3.13)

# Optional Pico SDK setup — ONLY if PICO_SDK_PATH is defined
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

# === mbedTLS Setup ===
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(ENABLE_TESTING OFF CACHE BOOL "")
set(ENABLE_CRYPTO_DRIVERS OFF CACHE BOOL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "")
set(MBEDTLS_CONFIG_FILE "\"mbedtls_config.h\"")
add_definitions(-DMBEDTLS_NO_PLATFORM_ENTROPY)

add_subdirectory(lib/mbedtls ${CMAKE_BINARY_DIR}/mbedtls_build EXCLUDE_FROM_ALL)

target_include_directories(mbedcrypto INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/config)

# Optional: patch Pico-specific time override
if(HAS_PICO_SDK)
  target_sources(mbedcrypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/library/mbedtls_time_alt.c)
  target_include_directories(mbedcrypto PRIVATE
    ${PICO_SDK_PATH}/src/common/pico_base/include
    ${PICO_SDK_PATH}/src/rp2_common/pico_time/include
  )
endif()

# === Our embedded crypto lib ===
add_library(sst_embedded
  src/sst_crypto_embedded.c
)

target_include_directories(sst_embedded PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/include
)

target_link_libraries(sst_embedded PUBLIC mbedcrypto)

# === Add subdirectories ===
add_subdirectory(sender)
add_subdirectory(receiver)
