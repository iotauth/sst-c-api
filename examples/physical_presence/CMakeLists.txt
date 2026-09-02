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
# only when both libraries are actually installed -- e.g. on the Raspberry
# Pi hardware, not on a development machine like macOS).
find_library(ASOUND_LIB asound)
find_library(GGWAVE_LIB ggwave)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND ASOUND_LIB AND GGWAVE_LIB)
  message(STATUS "ggwave/ALSA found: building --comm_type ultrasound support.")
  foreach(target robot locker)
    target_sources(${target} PRIVATE ../../ultrasonic_com/ggwave_sst_handshake.c)
    target_compile_definitions(${target} PRIVATE HAVE_GGWAVE_TRANSPORT)
    target_link_libraries(${target} ${ASOUND_LIB} ${GGWAVE_LIB})
  endforeach()
else()
  message(STATUS "ggwave/ALSA not found (or not on Linux): --comm_type ultrasound will report as unsupported.")
endif()
