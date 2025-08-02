cmake_minimum_required(VERSION 3.13)

# === Executable 1: pico_test_encrypt (Test Driver) ===
add_executable(pico_encrypt
    src/pico_test_encrypt.c
)

target_link_libraries(pico_encrypt PRIVATE
    pico_stdlib
    pico_rand
    sst_embedded
)

pico_enable_stdio_usb(pico_encrypt 1)
pico_enable_stdio_uart(pico_encrypt 0)
pico_add_extra_outputs(pico_encrypt)

# === Executable 2: LiFi Sender with Embedded Encryption ===
add_executable(lifi_sender_embedded
    src/lifi_sender_embedded.c
)

target_link_libraries(lifi_sender_embedded PRIVATE
    pico_stdlib
    pico_rand
    sst_embedded
)

pico_enable_stdio_usb(lifi_sender_embedded 1)
pico_enable_stdio_uart(lifi_sender_embedded 0)
pico_add_extra_outputs(lifi_sender_embedded)