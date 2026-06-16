# SST C++ Tests

This directory contains the C++ test suite for the SST C++ library. All tests are designed to validate the functionality of the C++ implementations that mirror the original C library.

## Test Structure

The test suite includes comprehensive unit tests covering all major functionalities of the SST library:

1. **c_crypto_test** - Cryptographic function tests (AES encryption/decryption, symmetric encrypt/decrypt with authentication)
2. **encrypt_buf_with_session_key_without_malloc_execution_time_test** - Performance timing measurements for encrypt/decrypt operations
3. **multi_thread_get_session_key_test** - Multi-threading safety tests for session key retrieval
4. **save_load_session_key_list_with_password_test** - Session key persistence tests with password encryption

## Running Tests

### Prerequisites
- CMake 3.19 or higher
- OpenSSL development libraries
- pthread library

### Build and Run Tests

```bash
# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project including tests
make

# Run all tests
ctest
```

### Individual Test Execution

Each test can be run directly:
```bash
# Run specific test (replace with actual test name)
./c_crypto_test path/to/config/file.config
```

## Configuration Files

The tests use the configuration files from `test_configs/` directory, which contain examples of various SST entity configurations. These include:
- Client configuration files for testing different encryption modes
- Various session key and distribution key configurations
- Network protocol settings

## Test Dependencies

All tests require valid configuration files to run. The test suite expects to find proper configuration files in the `test_configs/` directory with appropriate paths set up.