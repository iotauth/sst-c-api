cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

# Add the executable target
add_executable(receiver_uart
    src/receiver_uart.c
    ../../c_api.c
    ../../c_common.c
    ../../c_crypto.c
    ../../c_secure_comm.c
)

# Include paths for headers
target_include_directories(receiver_uart PRIVATE
    ${CMAKE_SOURCE_DIR}/../../include
    ${CMAKE_SOURCE_DIR}/../../  # for c_api.h and others in root
)

# Link against the embedded crypto library
target_link_libraries(receiver_uart PRIVATE
    sst_embedded
)
