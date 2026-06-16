# C++ test build file for sst-lib

cmake_minimum_required(VERSION 3.19)
project(sst-lib-tests VERSION 1.0.0 LANGUAGES CXX)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Test executables
add_executable(c_crypto_test cpp/tests/c_crypto_test.cpp)
target_link_libraries(c_crypto_test PRIVATE sst-c-api-cpp OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

add_executable(encrypt_buf_with_session_key_without_malloc_execution_time_test 
               cpp/tests/encrypt_buf_with_session_key_without_malloc_execution_time_test.cpp)
target_link_libraries(encrypt_buf_with_session_key_without_malloc_execution_time_test 
                       PRIVATE sst-c-api-cpp OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

add_executable(multi_thread_get_session_key_test 
               cpp/tests/multi_thread_get_session_key_test.cpp)
target_link_libraries(multi_thread_get_session_key_test 
                       PRIVATE sst-c-api-cpp OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

add_executable(save_load_session_key_list_with_password_test 
               cpp/tests/save_load_session_key_list_with_password_test.cpp)
target_link_libraries(save_load_session_key_list_with_password_test 
                       PRIVATE sst-c-api-cpp OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

# Enable testing
enable_testing()

# Add tests
add_test(NAME c_crypto_test COMMAND c_crypto_test)
add_test(NAME encrypt_buf_with_session_key_without_malloc_execution_time_test 
         COMMAND encrypt_buf_with_session_key_without_malloc_execution_time_test)
add_test(NAME multi_thread_get_session_key_test 
         COMMAND multi_thread_get_session_key_test)
add_test(NAME save_load_session_key_list_with_password_test 
         COMMAND save_load_session_key_list_with_password_test)