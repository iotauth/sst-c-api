# C++ IPFS example using the C API

These older C++ programs link `sst-c-api`. For the separate C++17 API based on `sst::SST_API` and `sst::ipfs`, use the [C++ API IPFS examples](../../../cpp/examples/ipfs_examples/README.md).

Here `$SST_ROOT` means the main `iotauth` repository root, with this submodule at `entity/c/`.

## Prerequisites

Use CMake 3.19 or newer, a C++ compiler, and OpenSSL 3 development headers. This example builds the static C library directly from the source tree; no system-wide installation is needed.

Follow the [C IPFS prerequisites](../c/README.md#prerequisites) to build Auth,
generate the file-sharing credentials, start Auth and IPFS, and create the
`plain_text` input file. Start the plain file system manager in a separate
terminal:

```sh
cd "$SST_ROOT/examples/file_sharing"
python3 file_system_manager.py
```

## Build

```sh
cd "$SST_ROOT/entity/c/examples/ipfs_examples/cpp"
cmake -S . -B build
cmake --build build
```

Use `-DCMAKE_BUILD_TYPE=Debug` during configuration to enable C API debug logging.

## Run the Example Entities

Run from `cpp/build/` so the config files' relative credential paths resolve:

```sh
cd "$SST_ROOT/entity/c/examples/ipfs_examples/cpp/build"
./uploader ../../uploader.config ../../plain_text ../../addReader.txt
```

When the uploader prints `Waiting for client to connect...`, run the downloader
in another terminal:

```sh
cd "$SST_ROOT/entity/c/examples/ipfs_examples/cpp/build"
./downloader ../../downloader.config
```

After the downloader finishes, the uploader resumes and compares file hashes.
