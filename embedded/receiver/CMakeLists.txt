cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

# Only require OpenSSL when NOT building for Pico
if(NOT DEFINED PICO_BOARD)
  find_package(OpenSSL REQUIRED)
endif()

# Executable
add_executable(receiver_uart
    src/receiver_uart.c
    ../../c_api.c
    ../../c_common.c
    ../../c_crypto.c
    ../../c_secure_comm.c
    ../../load_config.c
    ../../ipfs.c
)

# Includes
target_include_directories(receiver_uart PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
    ${CMAKE_SOURCE_DIR}/../../
)

if(OpenSSL_FOUND)
  target_include_directories(receiver_uart PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

# Link libraries
target_link_libraries(receiver_uart PRIVATE
    sst_embedded           # mbedTLS-based AES-GCM
)

if(OpenSSL_FOUND)
  target_link_libraries(receiver_uart PRIVATE OpenSSL::Crypto)  # for init_sst etc.
endif()
