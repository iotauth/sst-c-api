cmake_minimum_required(VERSION 3.19)
project(SST-Physical-Presence-Example VERSION 1.0.0 LANGUAGES C)

enable_testing()

# Include main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(robot robot.c)
add_executable(locker locker.c)

target_link_libraries(robot sst-c-api)
target_link_libraries(locker sst-c-api)

# UWB ranging's radio (a DWM3001CDK's serial CLI) and the Wi-Fi RSSI reader
# (iw over the dongle link): POSIX only, so always built; each reports an
# error at run time if its hardware is not attached.
foreach(target robot locker)
  target_sources(${target} PRIVATE ../../uwb_com/uwb_cli_dev.c
                                   ../../wifi_com/wifi_rssi.c)
  target_link_libraries(${target} Threads::Threads)
endforeach()

# Optional ggwave/ALSA-based ultrasound handshake transport (Linux only, and
# only when ALSA's dev package is installed and the ggwave submodule has been
# checked out at ../../ultrasonic_com/ggwave -- e.g. on the Raspberry Pi
# hardware, not on a development machine like macOS). ggwave itself is built
# from source here rather than found as a system library, since it's vendored
# as a submodule and never installed system-wide.
find_library(ASOUND_LIB asound)
set(GGWAVE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../ultrasonic_com/ggwave)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND ASOUND_LIB AND EXISTS ${GGWAVE_SRC_DIR}/CMakeLists.txt)
  message(STATUS "ggwave/ALSA found: building --comm_type ultrasound support.")
  add_subdirectory(${GGWAVE_SRC_DIR} ${CMAKE_BINARY_DIR}/ggwave-build)
  foreach(target robot locker)
    # The handshake transport, plus the acoustic I/O for the CO_LOCATION
    # keyed echo (whose protocol logic lives in sst-c-api).
    target_sources(${target} PRIVATE ../../ultrasonic_com/ggwave_sst_handshake.c
                                     ../../ultrasonic_com/ultrasonic_audio.c)
    target_compile_definitions(${target} PRIVATE HAVE_GGWAVE_TRANSPORT)
    target_link_libraries(${target} ${ASOUND_LIB} ggwave)
  endforeach()
else()
  message(STATUS "ggwave/ALSA not found (or not on Linux): --comm_type ultrasound will report as unsupported.")
endif()

# Optional pigpio-based IR handshake transport (Linux only, direct GPIO
# access, and requires root at runtime). pigpio is not an apt package on
# current Raspberry Pi OS -- see ../../ir_com/run_ir_test.sh for install
# steps.
find_library(PIGPIO_LIB pigpio)
set(IR_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../ir_com)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND PIGPIO_LIB AND EXISTS ${IR_SRC_DIR}/ir_sst_handshake.c)
  message(STATUS "pigpio found: building --comm_type ir support.")
  foreach(target robot locker)
    target_sources(${target} PRIVATE ../../ir_com/ir_sst_handshake.c)
    target_compile_definitions(${target} PRIVATE HAVE_IR_TRANSPORT)
    target_link_libraries(${target} ${PIGPIO_LIB} rt)
  endforeach()
else()
  message(STATUS "pigpio not found (or not on Linux): --comm_type ir will report as unsupported.")
endif()

# Optional pigpio-based LiFi (LED + phototransistor) handshake transport and
# HK adapter. Same pigpio/root requirements as IR; see ../../lifi_com/README.md.
set(LIFI_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../lifi_com)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND PIGPIO_LIB AND EXISTS ${LIFI_SRC_DIR}/lifi_sst_handshake.c)
  message(STATUS "pigpio found: building --comm_type lifi support.")
  foreach(target robot locker)
    target_sources(${target} PRIVATE ../../lifi_com/lifi_sst_handshake.c)
    target_compile_definitions(${target} PRIVATE HAVE_LIFI_TRANSPORT)
    target_link_libraries(${target} ${PIGPIO_LIB} rt)
  endforeach()
else()
  message(STATUS "pigpio not found (or not on Linux): --comm_type lifi will report as unsupported.")
endif()

# Optional BlueZ-based Bluetooth LE handshake transport and the BLE RSSI
# CO_LOCATION check over it (Linux only, libbluetooth-dev installed, and
# requires root at runtime for advertising and raw HCI commands). The RSSI
# check's protocol logic lives in sst-c-api; this adds the radio side.
find_library(BLUETOOTH_LIB bluetooth)
find_path(BLUETOOTH_INCLUDE bluetooth/l2cap.h)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BLUETOOTH_LIB AND BLUETOOTH_INCLUDE)
  message(STATUS "BlueZ found: building --comm_type bluetooth support.")
  foreach(target robot locker)
    target_sources(${target} PRIVATE ../../bluetooth_com/bt_link.c
                                     ../../bluetooth_com/bt_sst_handshake.c)
    target_compile_definitions(${target} PRIVATE HAVE_BT_TRANSPORT)
    target_link_libraries(${target} ${BLUETOOTH_LIB})
  endforeach()
else()
  message(STATUS "BlueZ not found (or not on Linux): --comm_type bluetooth will report as unsupported.")
endif()
