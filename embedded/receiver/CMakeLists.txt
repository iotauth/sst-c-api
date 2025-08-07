cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

# Only require OpenSSL when NOT building for Pico
if(NOT DEFINED PICO_BOARD)
  find_package(OpenSSL REQUIRED)
endif()

# Executable
add_executable(receiver_flash
    src/receiver_flash.c
    ../../c_api.c
    ../../c_common.c
    ../../c_crypto.c
    ../../c_secure_comm.c
    ../../load_config.c
    ../../ipfs.c
)

# Includes
target_include_directories(receiver_flash PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
    ${CMAKE_SOURCE_DIR}/../../
)

if(OpenSSL_FOUND)
  target_include_directories(receiver_flash PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# Link libraries
target_link_libraries(receiver_flash PRIVATE
    sst_embedded           # mbedTLS-based AES-GCM
)

if(OpenSSL_FOUND)
  target_link_libraries(receiver_flash PRIVATE OpenSSL::Crypto)  # for init_sst etc.
endif()

target_compile_definitions(receiver_flash PRIVATE
    DEFAULT_SST_CONFIG_PATH="../../receiver/sst.config"
)
