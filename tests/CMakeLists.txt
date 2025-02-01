cmake_minimum_required(VERSION 3.19)
project(SST_TEST LANGUAGES C)

# Add the root directory, which contains the sst-c-api library
add_subdirectory(.. sst-build)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Create test executables
add_executable(c_crypto_test c_crypto_test.c)
add_executable(multi_thread_get_session_key_test multi_thread_get_session_key_test.c)
add_executable(save_load_session_key_list_with_password_test save_load_session_key_list_with_password_test.c)
add_executable(encrypt_buf_with_session_key_without_malloc_execution_time_test encrypt_buf_with_session_key_without_malloc_execution_time_test.c)

# Link the test executables with the compiled library from root
target_link_libraries(c_crypto_test sst-c-api)
target_link_libraries(multi_thread_get_session_key_test sst-c-api)
target_link_libraries(save_load_session_key_list_with_password_test sst-c-api)
target_link_libraries(encrypt_buf_with_session_key_without_malloc_execution_time_test sst-c-api)

# Compiler warnings
if(MSVC)
  target_compile_options(c_crypto_test PRIVATE /W4 /WX)
  target_compile_options(multi_thread_get_session_key_test PRIVATE /W4 /WX)
  target_compile_options(save_load_session_key_list_with_password_test PRIVATE /W4 /WX)
  target_compile_options(encrypt_buf_with_session_key_without_malloc_execution_time_test PRIVATE /W4 /WX)
else()
  target_compile_options(c_crypto_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(multi_thread_get_session_key_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(save_load_session_key_list_with_password_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_compile_options(encrypt_buf_with_session_key_without_malloc_execution_time_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Enable testing
enable_testing()
add_test(NAME c_crypto_test COMMAND c_crypto_test)
add_test(NAME multi_thread_get_session_key_test COMMAND multi_thread_get_session_key_test)
add_test(NAME save_load_session_key_list_with_password_test COMMAND save_load_session_key_list_with_password_test)
add_test(NAME encrypt_buf_with_session_key_without_malloc_execution_time_test COMMAND encrypt_buf_with_session_key_without_malloc_execution_time_test)
