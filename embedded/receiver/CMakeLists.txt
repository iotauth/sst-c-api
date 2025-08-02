cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

# Add the executable target
add_executable(receiver_uart
    src/receiver_uart.c
)

# Include path for sst_crypto_embedded.h and other headers
target_include_directories(receiver_uart PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
)

# Link against the embedded crypto library defined in top-level CMakeLists
target_link_libraries(receiver_uart PRIVATE
    sst_embedded
)
