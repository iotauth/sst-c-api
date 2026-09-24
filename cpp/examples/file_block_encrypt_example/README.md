# C++ file block encryption example

This standalone example uses `sst::Crypto` to encrypt an input file in 1 KiB blocks with AES-128-CBC. It generates a random AES key locally and saves it as raw bytes for the reader. It does not contact Auth or load entity configs.

The [C block example](../../../examples/file_block_encrypt_example/README.md) demonstrates Auth-issued session keys and key-list persistence instead.

## Build

From this directory, with the [C++ prerequisites](../../README.md#requirements) installed:

```sh
cmake -S . -B build
cmake --build build
```

## Run

Create an input file named `input.txt`, then run:

```sh
./build/block_writer input.txt encrypted.bin key.bin
./build/block_reader encrypted.bin key.bin recovered.txt input.txt
```

The writer takes the input, encrypted-output, and key-file paths. Each encrypted record contains a 16-byte IV, a four-byte big-endian ciphertext length, and ciphertext.

The reader takes the encrypted file, key file, and recovered-output path. Its optional fourth argument supplies the original file for comparison. This demonstrates raw CBC block encryption; it does not add an HMAC or SST secure-message framing.
