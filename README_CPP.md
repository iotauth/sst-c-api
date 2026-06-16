# SST C++ Implementation

This directory contains a complete C++ implementation of the SST (Secure Session Transport) library that mirrors the functionality of the original C implementation. The C++ version maintains full API compatibility while providing modern C++ benefits when needed.

## Directory Structure

```
.
├── src/                 # Original C implementation (for reference)
├── cpp/                 # Complete C++ implementation
│   ├── CMakeLists.txt   # C++ library build configuration
│   ├── c_api.cpp/hpp    # Main API implementation
│   ├── c_common.cpp/hpp # Common utilities
│   ├── c_crypto.cpp/hpp # Cryptographic functions
│   ├── c_secure_comm.cpp/hpp # Secure communication
│   └── load_config.cpp/hpp # Configuration loading
├── tests/               # Original C tests (for reference)
└── cpp/tests/           # C++ test suite
    ├── CMakeLists.txt   # C++ tests build configuration
    └── test_configs/    # Test configuration files
```

## Building the C++ Library

### Prerequisites
- CMake 3.19 or higher
- OpenSSL development libraries (`libssl-dev` or equivalent)
- pthread library
- C++17 compatible compiler

### Build Commands

```bash
# Create build directory for C++ version
mkdir build_cpp && cd build_cpp

# Configure C++ build with debug symbols
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build the C++ library and tests
make

# Run all unit tests
ctest
```

## Building Both Versions (C and C++)

You can build both versions in parallel using separate directories:

```bash
# Build original C version
cd /path/to/sst-c-api/build_c
cmake .. -DCMAKE_BUILD_TYPE=Release
make

# Build C++ version  
cd /path/to/sst-c-api/build_cpp
cmake .. -DCMAKE_BUILD_TYPE=Release
make

# Run both test suites
cd /path/to/sst-c-api/build_c
ctest  # Run C tests

cd /path/to/sst-c-api/build_cpp
ctest  # Run C++ tests
```

## Key Features of C++ Implementation

1. **Full API Compatibility**: All original functions work exactly as in the C version
2. **Memory Management**: Preserved all malloc/free patterns from original C  
3. **Error Handling**: Same error codes and reporting behavior
4. **Thread Safety**: Maintained existing pthread constructs 
5. **Modern C++ Benefits**: Can use modern C++ features where appropriate
6. **Build System Ready**: Full CMake integration

## Running Tests

### Test Structure
The test suite includes comprehensive tests for all major functionality:

1. `c_crypto_test` - Crypto function tests (AES encryption/decryption)
2. `encrypt_buf_with_session_key_without_malloc_execution_time_test` - Performance timing tests  
3. `multi_thread_get_session_key_test` - Multi-threading safety tests
4. `save_load_session_key_list_with_password_test` - Session key persistence tests

### Test Execution
```bash
# Run all C++ tests
ctest

# Run specific test with config file
./c_crypto_test path/to/test_config.config

# Run test with verbose output
./c_crypto_test -v path/to/test_config.config
```

## Library Usage

The C++ library is fully compatible with existing C code. You can link it in either C or C++ projects:

### In C++ Projects:
```cpp
#include "c_api.hpp"

// Use all functions exactly as in C, but with C++ linkage
SST_ctx_t* ctx = init_SST("config.config");
// ... rest of your code
```

### In C Projects:
```c
#include "c_api.h"

// Use the same API as original C version
SST_ctx_t* ctx = init_SST("config.config");
// ... rest of your code  
```

## Integration Notes

- The `cpp/` directory contains **fully independent** implementations that mirror the original functionality
- Both C and C++ versions can coexist in the same project environment
- Use separate build directories to avoid conflicts
- Test configuration files are shared between both versions for consistency
- All tests validate identical functionality across implementations

## Version Management

The design allows you to:
- Compare performance between C and C++ implementations  
- Migrate gradually from C to C++
- Maintain backward compatibility with existing C codebases
- Select the appropriate implementation based on project requirements

## Directory Naming Convention

- **`src/`**: Original C source files (reference only)
- **`cpp/`**: Complete C++ implementations that mirror `src/`
- **`tests/`**: Original C test suite (for reference)  
- **`cpp/tests/`**: Equivalent C++ test suite using the same config files

This structure ensures that both versions remain synchronized while allowing independent development and testing.