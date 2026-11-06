# Running the SST C++ API tests

Run these commands from `entity/c/cpp/` in the iotauth checkout, or `cpp/` in
an sst-c-api checkout. A C++17 compiler, CMake 3.19 or newer, OpenSSL development
headers, and spdlog are required; see [README.md](README.md).

## Unit tests

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The checks in the test suites are always enabled, so they run in Release builds
(which CI uses) as well as in Debug builds; new tests must not rely on `assert()`,
which Release builds compile out. The five suites
are `crypto_test`, `socket_test`, `api_test`, `message_test`, and `protocol_test`.
They do not require Auth or IPFS services. Socket tests bind IPv4 and IPv6
loopback addresses on OS-selected ports. The protocol test also binds a local
port for an Auth stand-in and checks the handshake wire format.

## Auth integration

Generate the example credentials and start Auth as described in the
[server/client example](examples/server_client_example/README.md). That example
covers key requests, the entity handshake, encrypted messaging, and concurrent
key requests by ID.

For a session-key request alone, build the optional probe:

```sh
cmake --build build --target auth_connect_test
cd examples/server_client_example
../../build/auth_connect_test ../../../examples/server_client_example/c_client.config
```

The probe uses the Auth address and credentials from the config. Run it from
the directory shown so the credential paths in the example config resolve.

Other integration examples:

- [File block encryption](examples/file_block_encrypt_example/README.md): local
  encryption/decryption round trip, with no running services required.
- [IPFS file sharing](examples/ipfs_examples/README.md): requires Auth, IPFS, and
  a file system manager.
