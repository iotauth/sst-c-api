# SST C++ Cryptography API

A C++ cryptography API for SST
([docs](https://iotauth.github.io/docs/c-api-reference/)), built on OpenSSL.

It provides the cryptographic primitives used by SST: RSA key loading,
public-key encryption/decryption, SHA-256 digests, RSA sign/verify, AES
encryption (CBC / CTR / GCM), and symmetric encrypt-then-authenticate.

## Design

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

The API performs **no dynamic allocation** (`new` / `malloc` / `std::vector`
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
├── src/
│   ├── crypto.hpp        # public API
│   └── crypto.cpp        # implementation
└── tests/
    └── crypto_test.cpp   # unit test
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

Or run the test executable directly:

```sh
./build/crypto_test
```

A successful run ends with:

```
All C++ crypto tests passed.
```

## What the test covers

`tests/crypto_test.cpp` exercises the API with stack buffers only:

1. `Crypto::encrypt_aes()` / `Crypto::decrypt_aes()` round-trip for
   AES-128 **CBC**, **CTR**, and **GCM**.
2. `Crypto::symmetric_encrypt_authenticate()` /
   `Crypto::symmetric_decrypt_authenticate()` for all three modes,
   **with** and **without** HMAC, into stack `std::array` buffers.
3. `Crypto::digest_message_sha256()` determinism plus a
   `Crypto::sha256_sign()` / `Crypto::sha256_verify()` round-trip using a
   freshly generated in-memory RSA key pair (and a tampered-message negative
   check).

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
