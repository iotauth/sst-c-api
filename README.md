# Overview
---
This is a repository for the C and C++ APIs of **[SST (Secure Swarm Toolkit)](https://github.com/iotauth/iotauth)** as a submodule.

- The **C API** (`src/`) is the reference implementation of the SST entity protocol.
- The **C++ API** (`cpp/`) is a port of the C API to modern C++ (RAII, exceptions, zero-allocation crypto). It speaks the same wire protocol, so C and C++ entities interoperate with each other and with Auth. See [C++ API](#c-api-1) below.

# Prerequisites

-   OpenSSL:
    SST uses the APIs from OpenSSL for encryption and decryption. OpenSSL 3.0 and above is required to run SST.
    -   On macOS, OpenSSL can be installed using `brew install openssl`.
    -   The following environment variables need to be set before running `make`. The exact variable values can be found from the output of `brew install openssl`.
    -   Add two lines below by using `vi ~/.zshrc`
        -   `export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"`
        -   `export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"`
    -   Alternatively, point CMake at Homebrew's OpenSSL with `export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`.

    - For Linux users, check [here](https://linuxhint.com/install-openssl-3-from-source/) for installation.
-   CMake 3.19 or later.
-   For the C++ API, a C++17 compiler (clang or gcc).

# Repository Layout

```
entity/c/
├── src/            # C API (c_api.h is the public header)
├── cpp/            # C++ API, its examples and tests (see cpp/README.md)
├── examples/       # C examples (server/client, file block encryption, IPFS)
├── tests/          # C unit and integration tests
├── embedded/       # C API for embedded targets
├── cmake/          # CMake package config for the installed library
└── .github/        # CI workflows for the C (ci.yml) and C++ (ci-cpp.yml) APIs
```

# C API

## Code Hierarchy

c_common -> c_crypto -> c_secure_comm -> c_api -> entity_client, entity_server

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; load_config --&uarr;

`ipfs.h` builds on `c_api.h` and adds the file sharing helpers used by the IPFS examples.

## Functions

The public header is [`src/c_api.h`](./src/c_api.h). Unless noted otherwise, functions that return a pointer return `NULL` on failure, and functions that return `int` return 0 on success and -1 on failure.

### Context and session keys

**SST_ctx_t \*init_SST(const char \*config_path)**

-   Loads the config file, the entity's private key and Auth's public key (or the permanent distribution key when `PermanentDistKeyMode=on`).
-   Returns the `SST_ctx_t` used by all other functions.

**session_key_list_t \*init_empty_session_key_list(void)**

-   Allocates an empty session key list with room for `MAX_SESSION_KEY` keys.

**session_key_list_t \*get_session_key(SST_ctx_t \*ctx, session_key_list_t \*existing_s_key_list)**

-   Requests `entityInfo.number_key` session keys from Auth for the configured purpose.
-   When `existing_s_key_list` is `NULL`, returns a new list. Otherwise appends the received keys to the existing list and returns it.

**session_key_list_t \*get_session_key_with_index(SST_ctx_t \*ctx, int purpose_index, session_key_list_t \*existing_s_key_list)**

-   Same as `get_session_key()` but uses the purpose at `purpose_index` (the config can hold two `entityInfo.purpose` entries).

**session_key_t \*get_session_key_by_ID(unsigned char \*target_session_key_id, SST_ctx_t \*ctx, session_key_list_t \*existing_s_key_list)**

-   Returns the session key with the given 8-byte ID. If it is not in `existing_s_key_list`, requests it from Auth by ID and adds it to the list.
-   Used by entity servers to obtain the key a client presents in its handshake.

### Secure sessions

**SST_session_ctx_t \*secure_connect_to_server(session_key_t \*s_key, SST_ctx_t \*ctx)**

-   Connects to the entity server from the config and runs the session key handshake as the client.

**SST_session_ctx_t \*secure_connect_to_server_with_socket(session_key_t \*s_key, int sock)**

-   Runs the client side of the handshake over a socket the caller already connected with `connect()`.

**SST_session_ctx_t \*server_secure_comm_setup(SST_ctx_t \*ctx, int clnt_sock, session_key_list_t \*existing_s_key_list)**

-   Runs the server side of the handshake on an accepted client socket. The session key is looked up in `existing_s_key_list` or fetched from Auth by ID.

**int send_secure_message(char \*msg, unsigned int msg_length, SST_session_ctx_t \*session_ctx)**

-   Encrypts `msg` with the session key and sends it as a `SECURE_COMM_MSG`. `msg_length` must not exceed `MAX_PAYLOAD_LENGTH`.

**int read_secure_message(unsigned char \*plaintext, SST_session_ctx_t \*session_ctx)**

-   Reads one `SECURE_COMM_MSG` from the session's socket, verifies and decrypts it, and copies the plaintext into the caller's buffer, which must hold `MAX_SECURE_COMM_MSG_LENGTH` bytes.
-   Returns the plaintext length, 0 when the peer closed the connection, or -1 on failure.

**void \*receive_thread_read_one_each(void \*session_ctx)**

-   Thread body that calls `read_secure_message()` in a loop and logs the received messages. Usage:

```
pthread_t thread;
pthread_create(&thread, NULL, &receive_thread_read_one_each, (void *)session_ctx);
```

### Encryption with a session key

**int encrypt_buf_with_session_key(session_key_t \*s_key, unsigned char \*plaintext, unsigned int plaintext_length, unsigned char \*\*encrypted, unsigned int \*encrypted_length)**
**int decrypt_buf_with_session_key(session_key_t \*s_key, unsigned char \*encrypted, unsigned int encrypted_length, unsigned char \*\*decrypted, unsigned int \*decrypted_length)**

-   Encrypt (and HMAC) or verify (and decrypt) a buffer with the session key.
-   These allocate the result buffer, which the caller must `free()`.

**int encrypt_buf_with_session_key_without_malloc(...)**
**int decrypt_buf_with_session_key_without_malloc(...)**

-   Same as above but write into a caller-provided buffer. Size it with `get_expected_encrypted_total_length()` / `get_expected_decrypted_maximum_length()` from `c_crypto.h`.

### Saving and loading session keys

**int save_session_key_list(session_key_list_t \*session_key_list, const char \*file_path)**
**int load_session_key_list(session_key_list_t \*session_key_list, const char \*file_path)**

-   Save or load a session key list to or from a file. Before loading, use `init_empty_session_key_list()` to provide the destination list.

**int save_session_key_list_with_password(session_key_list_t \*session_key_list, const char \*file_path, const char \*password, unsigned int password_len, const char \*salt, unsigned int salt_len)**
**int load_session_key_list_with_password(...)**

-   Same, but the file is additionally encrypted with a key derived from the password and salt.

### Utilities

**unsigned int convert_skid_buf_to_int(unsigned char \*buf, int byte_length)**

-   Converts a big-endian session key ID buffer to an integer.

**int generate_random_nonce(int length, unsigned char \*buf)**

-   Fills `buf` with `length` cryptographically secure random bytes.

**int secure_rand(int min, int max)**

-   Returns a cryptographically secure random integer in `[min, max]`, or -1 on failure.

**void SST_print_debug / SST_print_log / SST_print_error / SST_print_error_exit(const char \*fmt, ...)**

-   printf-style logging helpers. `SST_print_debug()` only prints when built with `-DCMAKE_BUILD_TYPE=Debug`. `SST_print_error_exit()` prints the error and exits the process.

### Freeing

**void free_session_key_list_t(session_key_list_t \*session_key_list)**
**void free_session_ctx(SST_session_ctx_t \*session_ctx)**
**void free_SST_ctx_t(SST_ctx_t \*ctx)**

-   Free the memory owned by a session key list, a session context, or the SST context (including the loaded keys). `free_session_ctx()` does not close the socket.

## Compile

For the rest of this document, we use $SST_ROOT for the root directory of [SST's main repository](https://github.com/iotauth/iotauth/).

```
$cd $SST_ROOT/entity/c
$mkdir build && cd build
$cmake ../
$make
```

Build with `cmake -DCMAKE_BUILD_TYPE=Debug ../` to enable `SST_print_debug()` output.

## Compile as Shared Library

The command below will install the library under `/usr/local/lib/`, and `c_api.h` will be installed as `/usr/local/include/sst-c-api/c_api.h`.

```
$mkdir build && cd build
$cmake ../
$make
$sudo make install
```

## Examples and Tests

-   C examples: see the [`examples/`](./examples/README.md) directory (server/client, file block encryption, IPFS file sharing).
-   C tests: see [`tests/`](./tests/README.md).

# C++ API

The C++ API lives in [`cpp/`](./cpp/) and is documented in [`cpp/README.md`](./cpp/README.md). It is organized in four layers:

| Layer | Location | Purpose |
|-------|----------|---------|
| **Crypto** | `cpp/src/crypto.hpp/cpp` | Stateless primitives (`sst::Crypto`): RSA, AES, SHA-256, HMAC, with no dynamic allocation |
| **Network** | `cpp/src/net/sockets.hpp/cpp` | RAII POSIX socket wrappers |
| **API** | `cpp/src/api.hpp/cpp`, `cpp/src/ipfs.hpp/cpp` | `sst::SST_API`, `sst::SessionKeyList`, `sst::SST_Session` and the `sst::ipfs` file sharing helpers |
| **Logging** | `cpp/src/log/log_manager.hpp/cpp` | spdlog-based logger |

The C concepts map to C++ classes as follows. Setup operations (construction, key requests, handshakes) throw `sst::SST_Exception` on failure; data-plane calls return status codes like the C API.

| C API | C++ API |
|-------|---------|
| `SST_ctx_t`, `init_SST()` | `sst::SST_API` (constructor loads the config and keys) |
| `get_session_key()`, `get_session_key_with_index()`, `get_session_key_by_ID()` | `SST_API::get_session_key()`, `get_session_key_with_index()`, `get_session_key_by_ID()` |
| `secure_connect_to_server()`, `server_secure_comm_setup()` | `SST_API::secure_connect_to_server()`, `server_secure_comm_setup()` |
| `session_key_list_t` | `sst::SessionKeyList` |
| `SST_session_ctx_t`, `send_secure_message()`, `read_secure_message()` | `sst::SST_Session` (owns the socket) with `send_secure_message()`, `read_secure_message()` |
| `ipfs.h` | `sst::ipfs` in `cpp/src/ipfs.hpp` |

The same config files drive both APIs, so a C++ entity can be dropped in wherever a C entity runs.

C++ documentation:

-   [`cpp/README.md`](./cpp/README.md): design, layout, build and test instructions, full C-to-C++ mapping.
-   [`cpp/examples/server_client_example/README.md`](./cpp/examples/server_client_example/README.md): secure server/client example and session keys by ID.
-   [`cpp/examples/ipfs_examples/README.md`](./cpp/examples/ipfs_examples/README.md): IPFS file sharing with the plain and secure file system managers.
-   [`cpp/RUN_TESTS.md`](./cpp/RUN_TESTS.md): running the C++ unit tests and the Auth connection test.

To build the C++ library and run its unit tests:

```
$cd $SST_ROOT/entity/c/cpp
$cmake -S . -B build
$cmake --build build
$ctest --test-dir build --output-on-failure
```

# For Developers

-   For C and C++ indentation, we use the Google style.
    -   To enable the Google style indentation in VSCode, follow the instructions below. ([Source](https://stackoverflow.com/questions/46111834/format-curly-braces-on-same-line-in-c-vscode))
        1. Go to Preferences -> Settings
        2. Search for `C_Cpp.clang_format_fallbackStyle`
        3. Click Edit, Copy to Settings
        4. Change from `"Visual Studio"` to `"{ BasedOnStyle: Google, IndentWidth: 4 }"`
    -   To format the code, follow the instructions on this [page](https://code.visualstudio.com/docs/editor/codebasics#_formatting).

-   To format all C/C++ source files in the repository using the project's clang-format style, run:
    ```
    make format
    ```
-   To check formatting without modifying files (exits with an error if any file is not properly formatted), run:
    ```
    make format-check
    ```
    Both commands operate on all `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, and `.hh` files, excluding the `build/` directory and `embedded/lib/`.

-   CI: [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs the C unit and integration tests, and [`.github/workflows/ci-cpp.yml`](./.github/workflows/ci-cpp.yml) runs the same integration tests with the C++ API.

*Last updated on September 17, 2026*
