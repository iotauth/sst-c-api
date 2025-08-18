cmake_minimum_required(VERSION 3.13)
project(receiver_uart_project C)

# Host build (Pi 4): SST C API needs OpenSSL
find_package(OpenSSL REQUIRED)

# ---- Common helpers (utils, serial, replay, config handler) ----
add_library(receiver_common
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/serial_linux.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/replay_window.c
  # ${CMAKE_CURRENT_SOURCE_DIR}/src/key_exchange.c   # enable when you add it
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/config_handler.c
)

target_include_directories(receiver_common
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include       # embedded/receiver/include
    ${CMAKE_CURRENT_LIST_DIR}/../include    # embedded/include (protocol.h, config_handler.h)
)

# ---- Executable ----
add_executable(receiver_flash
  ${CMAKE_CURRENT_SOURCE_DIR}/src/receiver_flash.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../c_api.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../c_common.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../c_crypto.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../c_secure_comm.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../load_config.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../ipfs.c
)

target_include_directories(receiver_flash
  PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include       # receiver/include
    ${CMAKE_CURRENT_LIST_DIR}/../include    # embedded/include
    ${CMAKE_CURRENT_LIST_DIR}/../../        # repo root for c_api.h, etc.
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(receiver_flash
  PRIVATE
    receiver_common
    sst_embedded          
    OpenSSL::Crypto
)


# Nice-to-haves
set_property(TARGET receiver_common receiver_flash PROPERTY C_STANDARD 11)
target_compile_options(receiver_flash PRIVATE -Wall -Wextra -Wno-unused-parameter)

# Quote the default config path define
target_compile_definitions(receiver_flash PRIVATE
  DEFAULT_SST_CONFIG_PATH=\"../../receiver/lifi_receiver.config\"
)
