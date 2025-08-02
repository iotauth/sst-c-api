cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

find_package(OpenSSL REQUIRED)

# Executable
add_executable(receiver_uart
    src/receiver_uart.c
    ../../c_api.c
    ../../c_common.c
    ../../c_crypto.c
    ../../c_secure_comm.c
)

# Includes
target_include_directories(receiver_uart PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
    ${CMAKE_SOURCE_DIR}/../../
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(receiver_uart PRIVATE
    sst_embedded           # mbedTLS-based AES-GCM
    OpenSSL::Crypto        # for init_SST and related
)
