# File block encryption example

This example models a block-oriented storage workload using Auth-issued session keys. The writer generates random byte buffers representing key-value entries, packs them into 32 KiB blocks, and pads unused space with zeros. It writes three encrypted files with ten blocks each, using one session key per file.

The reader loads the metadata, requests each file's session key by ID from Auth, decrypts the blocks, and compares them with the saved plaintext.

## Build and prepare

Set `$SST_ROOT` to the main [SST repository](https://github.com/iotauth/iotauth). Generate credentials with `./generateAll.sh` in `$SST_ROOT/examples`, then build Auth with `mvn clean install` in `$SST_ROOT/auth/auth-server`.

```sh
cd "$SST_ROOT/entity/c/examples/file_block_encrypt_example"
cmake -S . -B build
cmake --build build
```

In a separate terminal, leave Auth running:

```sh
cd "$SST_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

## Write, then read

Run both programs from the same `build/` directory so the credential paths and generated files resolve correctly:

```sh
cd "$SST_ROOT/entity/c/examples/file_block_encrypt_example/build"
./block_writer ../block_writer.config
./block_reader ../block_reader.config
```

The writer produces:

- `encrypted0.txt` through `encrypted2.txt`: encrypted blocks.
- `plaintext0.txt` through `plaintext2.txt`: originals for comparison.
- `encrypted_file_metadata.dat` and `plaintext_file_metadata.dat`: file/block offsets, lengths, and key information.
- `s_key_list.bin`: the session key list used by the writer.

Run the alternative reader to load the saved keys without requesting them from Auth:

```sh
./block_reader_load_s_key_list
```

Run it while the saved session keys are still valid. This variant expects the files produced by the writer in its current directory.

The [C++ block example](../../cpp/examples/file_block_encrypt_example/) is a separate standalone crypto demonstration: it encrypts an input file in 1 KiB blocks using a locally generated AES key, without Auth. It does not implement this C example's key-request and persistence workflow.
