# SST C++ IPFS examples

C++ counterparts of the C IPFS examples in
[`examples/ipfs_examples/c`](../../../examples/ipfs_examples/c), built on the
SST C++ API (`cpp/src/api.hpp` and `cpp/src/ipfs.hpp`). They reuse the C
example's config files and inputs from
[`examples/ipfs_examples`](../../../examples/ipfs_examples). The key paths in
those configs are relative to the current working directory, so run the
binaries from the `build/` directory as shown below.

Below, `$SST_ROOT` is the root directory of
[SST's main repository](https://github.com/iotauth/iotauth/).

## Prerequisites

1. Generate the file sharing credentials at `$SST_ROOT/examples`:
   `./generateAll.sh -g configs/file_sharing.graph`
   (only run `./cleanAll.sh` first if you intend to delete existing generated credentials and Auth databases).
2. [Install IPFS](https://docs.ipfs.tech/install/command-line/), run
   `ipfs init` once, then `ipfs daemon`.
3. Build the Auth server (`auth/README.md`) and start it at
   `$SST_ROOT/auth/auth-server`:
   `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

## Build

```
$ cd $SST_ROOT/entity/c/cpp/examples/ipfs_examples
$ mkdir build && cd build
$ cmake ../
$ make
```

Create a non-empty `plain_text` file in `$SST_ROOT/entity/c/examples/ipfs_examples/`. The reader-list file `addReader.txt` contains one JSON request per line, for example `{"AddReader":"net1.Bob"}`.

## Example 1: plain file system manager

Start the file system manager at `$SST_ROOT/examples/file_sharing`:

```
$ python3 file_system_manager.py
```

Then, in `$SST_ROOT/entity/c/cpp/examples/ipfs_examples/build`:

```
$ ./entity_uploader ../../../../examples/ipfs_examples/uploader.config ../../../../examples/ipfs_examples/plain_text ../../../../examples/ipfs_examples/addReader.txt
$ ./entity_downloader ../../../../examples/ipfs_examples/downloader.config
```

The uploader encrypts `plain_text` once per session key, adds each encrypted
file to IPFS and registers the CIDs. The downloader fetches and decrypts the
files as `result*.txt`.

## Example 2: secure file system manager

Start the secure file system manager at `$SST_ROOT/examples/file_sharing`
(install the Python package in a virtual environment first; no `PYTHONPATH` change is needed):

```sh
cd "$SST_ROOT/entity/python"
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
cd "$SST_ROOT/examples/file_sharing"
python3 secure_file_system_manager.py file_system_manager.config
```

The manager prompts for its database password. Keep this terminal running.

Then, in `$SST_ROOT/entity/c/cpp/examples/ipfs_examples/build`:

```
$ ./secure_entity_uploader ../../../../examples/ipfs_examples/secure_uploader.config ../../../../examples/ipfs_examples/plain_text ../../../../examples/ipfs_examples/addReader.txt
$ ./secure_entity_downloader ../../../../examples/ipfs_examples/secure_downloader.config
```

Here the CID and session key ID travel to and from the file system manager
inside SST secure sessions.
