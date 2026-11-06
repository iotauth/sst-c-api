cmake_minimum_required(VERSION 3.19)

project(SST_Testbed)

# Add the main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp lib/send_syn.cpp lib/metrics.cpp)
add_executable(testbed_helpers_test tests/helpers_test.cpp)

foreach(prog server client testbed_helpers_test)
    target_compile_features(${prog} PRIVATE cxx_std_20)
    target_link_libraries(${prog} sst-c-api Threads::Threads)
endforeach()

enable_testing()
add_test(NAME testbed_helpers_test
         COMMAND testbed_helpers_test "${CMAKE_CURRENT_BINARY_DIR}")
