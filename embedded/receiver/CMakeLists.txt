cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

add_executable(receiver_uart
    src/receiver_uart.c
)

# Add include path to sst_crypto_embedded.h
target_include_directories(receiver_uart PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
)

# Link to your embedded crypto implementation using mbedTLS
target_link_libraries(receiver_uart PRIVATE
    sst_embedded
)
