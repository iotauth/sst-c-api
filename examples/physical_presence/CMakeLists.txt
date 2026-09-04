cmake_minimum_required(VERSION 3.19)
project(SST-Physical-Presence-Example VERSION 1.0.0 LANGUAGES C)

# Include main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(robot robot.c)
add_executable(locker locker.c)

target_link_libraries(robot sst-c-api)
target_link_libraries(locker sst-c-api)

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
    target_sources(${target} PRIVATE ../../ultrasonic_com/ggwave_sst_handshake.c)
    target_compile_definitions(${target} PRIVATE HAVE_GGWAVE_TRANSPORT)
    target_link_libraries(${target} ${ASOUND_LIB} ggwave)
  endforeach()
else()
  message(STATUS "ggwave/ALSA not found (or not on Linux): --comm_type ultrasound will report as unsupported.")
endif()
