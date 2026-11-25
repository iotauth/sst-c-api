cmake_minimum_required(VERSION 3.19)

project(SST_Testbed)

# Add the main SST library
add_subdirectory(../../ ${CMAKE_BINARY_DIR}/sst-lib-build)

find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_executable(server server.cpp)
add_executable(client client.cpp lib/send_syn.cpp lib/metrics.cpp)
add_executable(testbed_helpers_test tests/helpers_test.cpp)
add_executable(testbed_server_context_test tests/server_context_test.cpp)

foreach(prog server client testbed_helpers_test testbed_server_context_test)
    target_compile_features(${prog} PRIVATE cxx_std_20)
    target_link_libraries(${prog} sst-c-api Threads::Threads)
endforeach()

enable_testing()
add_test(NAME testbed_helpers_test
         COMMAND testbed_helpers_test "${CMAKE_CURRENT_BINARY_DIR}")

add_test(NAME testbed_server_context_test COMMAND testbed_server_context_test)
add_test(NAME testbed_launcher_test COMMAND "${Python3_EXECUTABLE}"
         "${CMAKE_CURRENT_SOURCE_DIR}/tests/launcher_test.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(testbed_helpers_test testbed_server_context_test testbed_launcher_test
                     PROPERTIES TIMEOUT 15)
