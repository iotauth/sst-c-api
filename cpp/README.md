# SST C++ API

A C++ API for SST
([docs](https://iotauth.github.io/docs/c-api-reference/)), built on OpenSSL.

It provides cryptographic primitives, RAII socket wrappers, and a high-level
session API for SST communication. The project is organized into four layers:

| Layer | Location | Purpose |
|-------|----------|---------|
| **Crypto** | `src/crypto.hpp/cpp` | Stateless primitives — RSA, AES, SHA-256, HMAC |
| **Network** | `src/net/sockets.hpp/cpp` | RAII POSIX socket wrappers |
| **API** | `src/api.hpp/cpp` | High-level `SST_API` session management |
| **Logging** | `src/log/log_manager.hpp/cpp` | Singleton logger with rotating file output |

## Crypto Design

All entry points are grouped into the `sst::Crypto` class:

- The public cryptographic operations are **public** static methods.
- Helpers used only internally (`print_crypto_error`, `get_evp_cipher`,
  `get_symmetric_encrypt_authenticate_buffer`,
  `get_symmetric_decrypt_authenticate_buffer`) are **private** static methods.
- `sst::SignedData` is a small class holding an RSA-sized data block plus its
  RSA signature (fixed-size `std::array` members, so it lives on the stack).

The routines are stateless, so the public methods are `static` — `Crypto` acts
as a strongly-typed namespace rather than something to instantiate.

### No dynamic allocation

The **Crypto** module performs **no dynamic allocation** (`new` / `malloc` / `std::vector`
are not used anywhere in the module):

- Every routine writes its result into a **caller-provided buffer**, which at
  the call site is typically a stack `std::array` sized via the
  `get_expected_encrypted_total_length()` /
  `get_expected_decrypted_maximum_length()` helpers.
- The RSA routines (`public_encrypt`, `private_decrypt`, `sha256_sign`) take an
  output buffer plus an in/out length: set the length to the buffer capacity
  before the call; it returns the actual length.
- Internal temporaries are fixed-size stack buffers too: the HMAC verification
  tag uses a `std::array<unsigned char, MAX_MAC_KEY_SIZE>`, and
  `create_salted_password_to_32bytes()` digests `password || salt`
  **incrementally** (two `EVP_DigestUpdate` calls) instead of building a
  concatenation buffer.
- `EVP_PKEY*` key objects returned by the loaders are managed by OpenSSL's own
  internal allocator; the caller frees them with `EVP_PKEY_free`.

## Layout

```
cpp/
├── CMakeLists.txt        # builds the library + tests
├── README.md             # this file
├── examples/
│   ├── file_block_encrypt_example/   # block encrypt/decrypt via sst::Crypto
│   └── ipfs_examples/    # secure IPFS server (C++ sockets + C session API)
├── src/
│   ├── api.hpp/cpp       # high-level SST_API
│   ├── crypto.hpp/cpp    # cryptographic primitives (sst::Crypto)
│   ├── net/
│   │   └── sockets.hpp/cpp       # RAII TCP sockets
│   └── log/
│       └── log_manager.hpp/cpp   # spdlog-based logging
└── tests/
    ├── api_test.cpp      # API integration tests
    └── crypto_test.cpp   # crypto unit tests
```

## Requirements

- A C++17 compiler (clang or gcc)
- CMake >= 3.19
- OpenSSL (development headers)

On macOS with Homebrew, point CMake at the Homebrew OpenSSL if needed:

```sh
brew install openssl@3 cmake
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

## Build and run the tests

From this `cpp/` directory:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Or run the test executables directly:

```sh
./build/crypto_test
./build/socket_test
./build/api_test
```

A successful crypto test run ends with:

```
All C++ crypto tests passed.
```

## What the tests cover

- `tests/crypto_test.cpp` exercises the **Crypto** layer with stack buffers only:
  AES encrypt/decrypt round-trips (CBC, CTR, GCM), symmetric
  encrypt-then-authenticate with and without HMAC, SHA-256 digest
  determinism, and SHA-256 sign/verify with an in-memory RSA key pair.

- `tests/api_test.cpp` exercises the high-level **API** layer end-to-end
  against a real server: config-file parsing, Auth handshake, key
  distribution, session setup, and encrypted message exchange.

Full docs: [C API reference](https://iotauth.github.io/docs/c-api-reference/).

## Usage example

```cpp
#include "crypto.hpp"

#include <array>
#include <cstring>

using sst::Crypto;

// Encrypt-then-authenticate "Hello World!" with AES-128-CBC + HMAC-SHA256.
unsigned char cipher_key[sst::AES_128_KEY_SIZE_IN_BYTES];
unsigned char mac_key[sst::MAC_KEY_SHA256_SIZE];
Crypto::generate_nonce(sizeof(cipher_key), cipher_key);
Crypto::generate_nonce(sizeof(mac_key), mac_key);

const char msg[] = "Hello World!";
unsigned int msg_len = std::strlen(msg);

unsigned int cap = Crypto::get_expected_encrypted_total_length(
    msg_len, sst::AES_128_IV_SIZE, sst::MAC_KEY_SHA256_SIZE,
    sst::AES_128_CBC, sst::USE_HMAC);

std::array<unsigned char, 128> out{};  // cap <= 128 for this payload
unsigned int out_len = 0;
Crypto::symmetric_encrypt_authenticate(
    reinterpret_cast<const unsigned char*>(msg), msg_len,
    mac_key, sst::MAC_KEY_SHA256_SIZE,
    cipher_key, sst::AES_128_KEY_SIZE_IN_BYTES,
    sst::AES_128_IV_SIZE, sst::AES_128_CBC, sst::USE_HMAC,
    out.data(), &out_len);
```
