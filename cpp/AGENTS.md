# SST C++ API — Agent Instructions

## Important
You are building a High level CPP API. you can use `api.hpp` current structure to build on top of the current schelleton code. You have the freedom to change Objects naming according to the existing code base in `crypto.hpp/cpp` files.

## Build & Test

```bash
cd cpp
cmake -S . -B build && cmake --build build
ctest --test-dir build --output-on-failure
```

Three test targets: `crypto_test`, `socket_test`, `api_test`.

## Architecture

```
src/
├── api.hpp/cpp          # High-level API (SST_API)
├── crypto.hpp/cpp       # Stateless cryptographic primitives (sst::Crypto)
├── net/
│   └── sockets.hpp/cpp  # RAII POSIX socket wrappers
└── log/
    └── log_manager.hpp/cpp  # Singleton logger + LOG_INF / LOG_ERR / LOG_DBG / LOG_TRA macros
```

- `SST_API` — session management, Auth handshake orchestration.
- `Crypto` — all static methods; **no dynamic allocation** in this module.
- All public types live in `namespace sst`.

## Key Conventions

### No dynamic allocation in crypto
Every `Crypto::*` routine writes into a **caller-provided buffer**. Use the size helpers (`get_expected_encrypted_total_length`, `get_expected_decrypted_maximum_length`) to size stack buffers before calling. The class is used as a namespace grouping — never instantiate it.

### Smart pointers in net layer
The network layer (`sockets.hpp` / `sockets.cpp`) uses `std::make_unique<uint8_t[]>` to allocate address buffers. The `SST_SocketInfo::addr` member is a `unique_ptr<sockaddr>` with a custom deleter that casts the stored pointer back to `uint8_t*` before calling `delete[]`. `CreateAddr` fills a `sockaddr_in` / `sockaddr_in6` stack-allocated struct and copies it into the managed buffer via `std::copy`.

### RAII everywhere
- Sockets: `Socket`, `ClientSocket`, `ServerSocket` close FDs in destructors.

### Error handling
- Crypto/sockets return `-1` on failure (errors logged to stderr).
- API layer throws `sst::SST_Exception`.
- OpenSSL key objects (`EVP_PKEY*`) are caller-owned — **must** call `EVP_PKEY_free()`.

### Logging
Use macros: `LOG_INF`, `LOG_ERR`, etc. from `src/log/log_manager.hpp`. Note: if `GIT_VERSION` is defined at build time, logging becomes a no-op.

## Pitfalls

1. **OpenSSL keys**: `Crypto::load_auth_public_key()` and `load_entity_private_key()` return owning pointers — always free with `EVP_PKEY_free()`.
2. **Buffer sizing**: Always call the size helper before crypto operations; passing an undersized buffer causes silent truncation or OpenSSL errors.
3. **Non-blocking I/O**: Socket read/write temporarily sets `O_NONBLOCK` and restores it. Don't assume blocking mode persists across calls if exceptions occur.
4. **spdlog include path** in CMakeLists.txt is hardcoded to the build directory — out-of-source builds elsewhere may break.
5. **Config parsing constants**: When adding new `strncpy` calls in `parse_config_file`, use the matching `MAX_*_LENGTH` constant for that specific buffer. The `purpose` field uses `MAX_PURPOSE_LENGTH` (64), not `MAX_ENTITY_NAME_LENGTH` (32). Mismatching constants wastes buffer space and is fragile if constants are refactored.

## File Placement Rules (from AGENT_SPEC.md)

- New API code: `src/api.hpp`, `src/api.cpp`
- Tests: `tests/api_test.cpp`
- **DO NOT MODIFY**: `CMakeLists.txt`, `crypto.{hpp,cpp}`, `log/*.cpp/hpp`.
- **Safe to MODIFY**: `src/net/*.cpp/hpp` (already refactored for smart pointers).

## Related Documentation

- [Crypto API reference](https://iotauth.github.io/docs/c-api-reference/) — full C API docs.
- `README.md` — project overview and build instructions.
- `log/README.md` - overview of the utilization of `log_manager.hpp/cpp`
- `net/README.md` - overview of the utilization of `socket.hpp/cpp`

