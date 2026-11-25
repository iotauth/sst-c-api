# SST C IPFS examples

These programs use the C API to encrypt files with Auth-issued session keys,
store the ciphertext in IPFS, and share file metadata through a file system
manager. The manager has plain TCP and SST-secured variants.

Set `$SST_ROOT` to the main `iotauth` repository root. For the separate C++17 API,
see the [C++ API IPFS examples](../../../cpp/examples/ipfs_examples/README.md).

## Prerequisites

Follow the [shared Auth setup](../../README.md#shared-auth-setup), but generate
credentials and Auth databases with the file-sharing graph:

```sh
cd "$SST_ROOT/examples"
./generateAll.sh -g configs/file_sharing.graph -p asdf
```

Start (or restart) Auth101 with the matching password:

```sh
cd "$SST_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password=asdf
```

The examples invoke the `ipfs` command from `PATH`. Follow the main repository's
[file-sharing setup](https://github.com/iotauth/iotauth/tree/main/examples/file_sharing)
to install it, run `ipfs init` once, and leave `ipfs daemon` running in another
terminal. Python is needed for the file system managers.

Create a non-empty `plain_text` file in
`$SST_ROOT/entity/c/examples/ipfs_examples/`. The checked-in `addReader.txt`
contains one JSON request per line, such as `{"AddReader":"net1.Bob"}`.

## Build

```sh
cd "$SST_ROOT/entity/c/examples/ipfs_examples/c"
cmake -S . -B build
cmake --build build
```

The examples build the C library from source; no system-wide installation is
needed. Run from `c/build/` so relative credential paths resolve correctly.

## Plain file system manager

In a separate terminal:

```sh
cd "$SST_ROOT/examples/file_sharing"
python3 file_system_manager.py
```

Run the uploader, then the downloader:

```sh
cd "$SST_ROOT/entity/c/examples/ipfs_examples/c/build"
./entity_uploader ../../uploader.config ../../plain_text ../../addReader.txt
./entity_downloader ../../downloader.config
```

The uploader encrypts the input and registers the IPFS CIDs and session key IDs
with the manager. The downloader requests the keys from Auth and decrypts the
downloaded files into its working directory.

## Secure file system manager

Stop the plain manager first; both managers use port 22100 in these configs.
Install the Python API and start the secure manager in a separate terminal:

```sh
cd "$SST_ROOT/entity/python"
./initPythonEntities.sh
source .venv/bin/activate
cd "$SST_ROOT/examples/file_sharing"
python3 secure_file_system_manager.py file_system_manager.config
```

The manager prompts for its metadata database password, which is separate from
the Auth keystore password. For an existing database, follow the compatibility
and migration instructions in the main repository's
[file-sharing README](https://github.com/iotauth/iotauth/tree/main/examples/file_sharing).
Keep the manager running, then run:

```sh
cd "$SST_ROOT/entity/c/examples/ipfs_examples/c/build"
./secure_entity_uploader ../../secure_uploader.config ../../plain_text ../../addReader.txt
./secure_entity_downloader ../../secure_downloader.config
```

These variants exchange the CID and session key ID with the manager over SST
secure sessions; the encrypted files still travel through IPFS.
