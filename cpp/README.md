# SST C++ API

A C++ API for SST
([guide](https://iotauth.github.io/docs/cpp-guide/),
[API reference](https://iotauth.github.io/docs/cpp-api-reference/)), built on OpenSSL.

It provides cryptographic primitives, RAII socket wrappers, and a high-level
session API for SST communication. The project is organized into four layers:

| Layer | Location | Purpose |
|-------|----------|---------|
| **Crypto** | `src/crypto.hpp/cpp` | Stateless primitives — RSA, AES, SHA-256, HMAC |
| **Network** | `src/net/sockets.hpp/cpp` | RAII POSIX socket wrappers |
| **API** | `src/api.hpp` | Public `SST_API`, `SST_Session` and `SessionKeyList` interfaces |
| **Logging** | `src/log/log_manager.hpp/cpp` | Singleton logger with rotating file output |

## Crypto Design

All entry points are grouped into the `sst::Crypto` class:

- The public cryptographic operations are **public** static methods.
- Helpers used only internally (`print_crypto_error`, `get_evp_cipher`,
  `get_symmetric_encrypt_authenticate_buffer`,
  `get_symmetric_decrypt_authenticate_buffer`) are **private** static methods.

The routines are stateless, so the public methods are `static` — `Crypto` acts
as a strongly-typed namespace rather than something to instantiate.

### Caller-provided crypto buffers

The **Crypto** module uses caller-provided output buffers and fixed-size byte
arrays for temporary data:

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
- OpenSSL allocates key objects and operation contexts internally (including
  `EVP_PKEY_CTX` and `EVP_CIPHER_CTX`), so these routines are not allocation-free.
  The caller frees `EVP_PKEY*` objects returned by the loaders with `EVP_PKEY_free`.

## API Design

`src/api.hpp` is a C++ port of the SST C API (`src/c_api.h`). It speaks the
same wire protocol, so a C++ entity interoperates with Auth and with C
entities unchanged. The C concepts map to classes as follows:

| C API | C++ API |
|-------|---------|
| `SST_ctx_t`, `init_SST()` | `sst::SST_API` (constructor loads the config and keys) |
| `get_session_key()` / `get_session_key_with_index()` | `SST_API::get_session_key()` / `get_session_key_with_index()` |
| `get_session_key_by_ID()` | `SST_API::get_session_key_by_ID()` |
| `secure_connect_to_server()` / `..._with_socket()` | `SST_API::secure_connect_to_server()` / `..._with_socket()` |
| `server_secure_comm_setup()` | `SST_API::server_secure_comm_setup()` |
| `session_key_list_t` | `sst::SessionKeyList` (fixed-size circular list) |
| `SST_session_ctx_t` | `sst::SST_Session` (owns the socket, RAII) |
| `send_secure_message()` / `read_secure_message()` | `SST_Session::send_secure_message()` / `read_secure_message()` |
| `receive_thread_read_one_each()` | `SST_Session::receive_loop()` |
| `encrypt/decrypt_buf_with_session_key_without_malloc()` | `SST_API::encrypt/decrypt_buf_with_session_key()` |
| `send_add_reader_req_via_TCP()` | `SST_API::send_add_reader_req_via_TCP()` |
| `ipfs.h` file helpers | `sst::ipfs` functions in `src/ipfs.hpp` |

Setup operations (construction, key requests, handshakes) throw
`sst::SST_Exception` on failure. Its `code()` returns an `SST_ErrorCode`
category such as `Configuration`, `Network`, `Crypto`, `Protocol`, or
`AuthRejected`; `what()` contains the diagnostic text. The existing
single-argument exception constructor remains available with `Unspecified`.

The existing integer-returning message methods are unchanged: sends return
framed bytes written, receives return plaintext length, and failures return -1.
A return of 0 from a receive can mean either an empty plaintext or peer closure.
Use `send_secure_message_result()` and `read_secure_message_result()` to obtain
an `SST_IOResult` with `status`, `bytes`, and `error`. Its `Success`, `PeerClosed`,
and `Error` statuses distinguish those cases without parsing logs.

All Auth communication of one `SST_API` is serialized by an internal mutex.
Session key requests and add-reader requests share the same exchange code,
including nonce verification and distribution-key renewal. Key requests by
purpose and by ID use the same core request method; request purpose is local
and does not persist after a failed request.

`SessionKeyList` has no internal locking. Use a list from one thread at a time,
or hold an application mutex throughout calls that use it and accesses to its
keys. `at(index)` accesses active keys in oldest-to-newest order; `at_slot(slot)`
accesses an active storage slot returned by `find()` or `add()`. Both check
bounds. The public `num_key`, `rear_idx`, and `s_key` fields remain for source
compatibility; new code should use the accessors and `add()`/`append()`.

Key expiry is measured in Unix-epoch milliseconds using `system_clock`, matching
Auth's serialized absolute expiry values. `steady_clock` has an unrelated epoch
and cannot be compared directly with those values.

A receiver blocked in `read_secure_message()` is released with
`SST_Session::shutdown()`. Join that thread before destroying the session, whose
destructor closes the socket. The C++ API currently has no session-key save/load
methods equivalent to the C API.

## Message Classes

`src/message/` mirrors the Java message package of the Auth server
(`auth/library/src/main/java/org/iot/auth/message/`), one class per file in
namespace `sst::message`. The entity runs each message in the opposite
direction from Auth: it builds and encrypts requests, and decrypts and parses
responses.

Every wire message has the envelope `[msgType (1 byte)][payloadLen (varint)][payload]`.
The encrypted handshake body contains a separate field-presence bitmask, called
`indicator` in the [protocol reference](https://iotauth.github.io/docs/message-types).
The implementation names it `handshake_flags`. It is inside the encrypted payload;
it does not replace `msgType`. The C-compatible first handshake uses a compact
nonce-only body; the third includes both nonces. These existing wire encodings
are retained.

The Auth payload limit is 4096 bytes, excluding the envelope. Ten session keys
plus the RSA-encrypted distribution key and signature, crypto spec, IV, padding,
and MAC can exceed the C API's 1024-byte limit.

| Java (Auth server) | C++ (entity) | Entity side |
|--------------------|--------------|-------------|
| `MessageType` | `message_type.hpp` | enum of message type bytes |
| `IoTSPMessage` | `iotsp_message.hpp/cpp` | framing: `serialize()`, `read()`, `receive()` |
| `AuthHelloMessage` | `auth_hello_message.hpp/cpp` | parses Auth ID and nonce |
| `AuthAlertCode`, `AuthAlertMessage` | `auth_alert_code.hpp`, `auth_alert_message.hpp/cpp` | parses the alert code |
| `SessionKeyReqMessage` | `session_key_req_message.hpp/cpp` | builds and encrypts |
| `AddReaderReqMessage` | `add_reader_req_message.hpp/cpp` | builds and encrypts |
| `SessionKeyRespMessage` | `session_key_resp_message.hpp/cpp` | decrypts and parses session keys |
| `AddReaderRespMessage` | `add_reader_resp_message.hpp/cpp` | decrypts and parses |

Two base classes have no Java counterpart. `EntityReqMessage` holds the
encryption shared by both requests (distribution key, or public key plus
signature when the distribution key has expired). `EntityRespMessage` holds
the handling shared by both responses (the optional encrypted distribution
key and decryption with the distribution key). The messages are internal:
`api.hpp` does not expose them.

The config file format is the C API format (`entityInfo.name=...`); the
earlier C++ key names (`name = ...`) are still accepted. Relative credential
paths are resolved from the process working directory, not the config directory.
Canonical config keys and aliases share one field/validator table. Unknown keys,
malformed integers (including trailing characters), and more than two repeated
`entityInfo.purpose` entries are rejected.

## Layout

```
cpp/
├── CMakeLists.txt        # builds the library + tests
├── README.md             # this file
├── examples/
│   ├── file_block_encrypt_example/   # block encrypt/decrypt via sst::Crypto
│   ├── server_client_example/        # secure server/client via sst::SST_API
│   └── ipfs_examples/    # IPFS file sharing via sst::SST_API + sst::ipfs
├── src/
│   ├── api.hpp           # public SST_API, SessionKeyList, SST_Session interfaces
│   ├── api.cpp           # entity initialization and Auth requests
│   ├── config.cpp        # configuration parsing, defaults and validation
│   ├── handshake.cpp     # entity-to-entity session key handshakes
│   ├── session.cpp       # secure session lifetime and message I/O
│   ├── session_key.cpp   # key validity, key ring and buffer encryption
│   ├── ipfs.hpp/cpp      # IPFS file sharing helpers (sst::ipfs)
│   ├── api_internal.hpp/cpp  # shared byte, socket and crypto helpers (not public)
│   ├── message/          # Auth/entity messages (sst::message), one class
│   │                     # per file, mirroring org.iot.auth.message
│   ├── crypto.hpp/cpp    # cryptographic primitives (sst::Crypto)
│   ├── net/
│   │   └── sockets.hpp/cpp       # RAII TCP sockets
│   └── log/
│       └── log_manager.hpp/cpp   # spdlog-based logging
└── tests/
    ├── api_test.cpp      # API unit tests (config, key lists, encryption)
    ├── crypto_test.cpp   # crypto unit tests
    ├── message_test.cpp  # message classes vs. the Auth wire formats
    ├── socket_test.cpp   # socket unit tests
    ├── temporary_directory.hpp # private, automatically cleaned test directories
    └── protocol_test.cpp # local Auth stand-in and handshake wire regression tests
```

## Requirements

- A C++17 compiler (clang or gcc)
- CMake >= 3.19
- OpenSSL 3 development headers
- A POSIX environment (Linux or macOS)
- spdlog, supplied as an installed CMake package, a local source tree, or fetched
  by CMake (the fallback requires Git and network access)

SonarCloud automatic analysis is configured for C++17 in the repository's
`.sonarcloud.properties`, matching CMake. Recommendations for newer facilities
such as `std::span`, `std::jthread`, and `std::format` do not apply to this API.
SonarCloud reads that file from the default branch; to use the same setting on
a pull request before merging it, set `sonar.cfamily.reportingCppStandardOverride`
to `c++17` in the project's analysis settings.

Four local `NOSONAR` comments retain existing public member signatures:
`Connect()`, `Accept()`, `shutdown()`, and the `std::string` secure-send overload.
Changing their const qualification or parameter type would break existing
member-function pointers or binary callers. Internal helpers follow the newer
recommendations where they are compatible with C++17.

On macOS with Homebrew, point CMake at the Homebrew OpenSSL if needed:

```sh
brew install openssl@3 cmake
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

### Offline spdlog setup

CMake first reuses an existing `spdlog::spdlog` target or finds an installed
spdlog package. Set `-DSST_FETCH_SPDLOG=OFF` to disable its network fallback.
For an installed package outside the usual search paths:

```sh
cmake -S . -B build -DSST_FETCH_SPDLOG=OFF -DCMAKE_PREFIX_PATH=/path/to/prefix
```

Or provide an existing spdlog source checkout:

```sh
cmake -S . -B build -DSST_FETCH_SPDLOG=OFF -DSST_SPDLOG_SOURCE_DIR=/path/to/spdlog
```

When no local dependency is supplied and fetching is enabled, CMake downloads
spdlog v1.17.0.

## Build and run the tests

Run tests from a writable directory. Tests that generate credentials create a
unique directory there with owner-only permissions and remove it on completion.
CTest uses the build directory as the working directory.

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
./build/message_test
./build/protocol_test
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

- `tests/api_test.cpp` exercises the high-level **API** layer without a
  server: config-file parsing (including error cases), session key list
  bookkeeping, and session key encryption/decryption round trips.

- `tests/socket_test.cpp` checks IPv4/IPv6 loopback connections, invalid
  addresses, descriptor ownership and duplication, and reads at peer closure.

- `tests/message_test.cpp` checks each message class against the wire
  format of its Java counterpart in the Auth server: framing, AUTH_HELLO and
  AUTH_ALERT parsing, request payloads under both distribution key and public
  key encryption, and response decryption with and without a new
  distribution key.

- `tests/protocol_test.cpp` uses a local Auth stand-in to verify public-key and
  distribution-key requests for both session keys and add-reader operations,
  key-ID lookups and cache hits, nonce/alert failures, responses larger than
  1024 bytes, and the outer msgType versus encrypted handshake flags.

- `examples/server_client_example` covers the Auth handshake, key
  distribution, session setup and encrypted message exchange end-to-end
  against a running Auth; it runs in the C++ integration test workflow.

Full docs: [C++ Guide](https://iotauth.github.io/docs/cpp-guide/) and
[C++ API Reference](https://iotauth.github.io/docs/cpp-api-reference/).
The CMake project builds a static `sst-cpp-api` target; it currently has no
install/package-export rules. Build examples from their own CMake directories.

## Usage example

```cpp
#include "crypto.hpp"

#include <array>
#include <cstring>

int main() {
    using sst::Crypto;

    // Encrypt "Hello World!" with AES-128-CBC + HMAC-SHA256.
    unsigned char cipher_key[sst::AES_128_KEY_SIZE_IN_BYTES];
    unsigned char mac_key[sst::MAC_KEY_SHA256_SIZE];
    if (Crypto::generate_nonce(sizeof(cipher_key), cipher_key) != 0 ||
        Crypto::generate_nonce(sizeof(mac_key), mac_key) != 0) {
        return 1;
    }
    const char msg[] = "Hello World!";
    unsigned int msg_len = std::strlen(msg);
    unsigned int capacity = Crypto::get_expected_encrypted_total_length(
        msg_len, sst::AES_128_IV_SIZE, sst::MAC_KEY_SHA256_SIZE,
        sst::AES_128_CBC, sst::USE_HMAC);
    std::array<unsigned char, 128> out{};
    if (capacity > out.size()) return 1;
    unsigned int out_len = 0;
    return Crypto::symmetric_encrypt_authenticate(
        reinterpret_cast<const unsigned char*>(msg), msg_len,
        mac_key, sizeof(mac_key), cipher_key, sizeof(cipher_key),
        sst::AES_128_IV_SIZE, sst::AES_128_CBC, sst::USE_HMAC,
        out.data(), &out_len) < 0 ? 1 : 0;
}
```
