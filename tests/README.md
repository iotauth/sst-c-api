# Tests for the SST C API

Set `$SST_ROOT` to the absolute path of the main `iotauth` repository, with
`sst-c-api` checked out at `$SST_ROOT/entity/c`.
The separate C++ API tests are documented in [cpp/README.md](../cpp/README.md#build-and-run-the-tests).

## Standalone tests

Configure from `entity/c/` to build the C library and its three standalone tests:

```sh
cd "$SST_ROOT/entity/c"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

These tests need OpenSSL and a POSIX environment, but no running Auth server or
IPFS daemon. Debug builds retain the assertions in the older crypto test. The
resource-cleanup and Auth-request regression tests use always-on checks, and
CI also runs this suite in Release mode.

| CTest / executable name | Source | Coverage |
|---|---|---|
| `crypto_test` | `c_crypto_test.c` | C crypto primitives |
| `resource_cleanup_test` | `resource_cleanup_test.c` | Invalid configs, descriptor cleanup, binary file reads, integer decoding and handshake failure paths |
| `auth_request_test` | `auth_request_test.c` | Session-key and add-reader requests over local socket pairs, public-key and distribution-key encryption, and write failures |

CTest supplies a writable build-directory argument to `resource_cleanup_test`;
the test creates and removes its own private directory there. To run it directly
from `entity/c/`:

```sh
./build/resource_cleanup_test "$PWD/build"
```

## Integration tests with Auth

Follow the [shared Auth setup](../examples/README.md#shared-auth-setup) using the
default graph, and leave Auth101 running. Then build the separate `tests/`
CMake project:

```sh
cd "$SST_ROOT/entity/c/tests"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cd build
```

Run the programs from `tests/build/`, since the credential paths in
`test_configs/client.config` are relative to the working directory:

```sh
./c_crypto_test
./save_load_session_key_list_with_password_test ../test_configs/client.config
./multiple_request_get_session_key_test ../test_configs/client.config
```

The crypto executable in this project is named `c_crypto_test`; the root project
names the same test `crypto_test`. This project also builds the root project's
standalone tests under `sst-build/`.

| Executable | Purpose |
|---|---|
| `save_load_session_key_list_with_password_test` | Save and reload password-encrypted session-key lists |
| `multiple_request_get_session_key_test` | Sequential key requests, list capacity and append behavior |
| `multi_thread_get_session_key_test` | Five concurrent requests sharing one C context after an initial distribution-key request |
| `encrypt_buf_with_session_key_without_malloc_execution_time_test` | Benchmark caller-buffer encryption and decryption with Auth-issued keys |

To run the shared-context stress test and encryption benchmark manually:

```sh
./multi_thread_get_session_key_test ../test_configs/client.config
./encrypt_buf_with_session_key_without_malloc_execution_time_test ../test_configs/client.config
```

The multithreaded C test intentionally leaves its mutex calls commented out and
can fail nondeterministically. It does not establish that sharing a C context
without application locking is safe. The C++ API's Auth requests have internal
locking and separate [threaded examples](../cpp/examples/server_client_example/README.md#example-2-session-keys-by-id-from-multiple-threads).

The Auth-dependent entries in `tests/CMakeLists.txt` currently register these
executables with CTest **without their required config argument**. Run them
directly as shown above; an unfiltered `ctest` in `tests/build/` is not a working
integration-test command. Use the root build for the standalone CTest suite.

The [C CI workflow](../.github/workflows/ci.yml) runs both the password save/load
test and `multi_thread_get_session_key_test`, alongside the server/client,
block-encryption and IPFS examples. The shared-context test remains enabled
despite the nondeterministic behavior described above; only the encryption
benchmark command is commented out.
