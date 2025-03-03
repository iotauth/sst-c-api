# File block encrypt example

This is a simple example for RocksDB block encryption.

It randomly creates key_values (implemented as random buffers), append the created random key_values into a block with a maximum size 32kbytes.
The leftover space is filled with zero padding.
Then the entire buffer is encrypted into a single block. Append the `TOTAL_BLOCK_NUM`(10) blocks, and save them as a single file.

The detailed logic is as below.

### Encrypting part. `block_writer.c`

1. Create random key_values, with a size between 56~144 bytes.
2. The key_values are appended until the total size is 32 kbytes.
3. When the next key_value does not fit to the maximum block size(32kybtes), the leftover size is filled with zero-paddings. The leftover buffer will be used in the next block.
4. The block is now 32kbytes, and it is encrypted with a session key.
5. 1~5 is repeated, appending 10 blocks, making a single file.
6. 5 is repeated, making three separate files, `encrypted'i'.txt`. Each file uses different session keys.
7. To test if the encryption decryption worked prorperly, we save `plaintext'i'.txt`, which is the blocks not encrypted.
8. The metadata is saved inside `encrypted_file_metadata.dat`. Same with `plaintext_file_metadata.dat`. It saves the used session key id for the file.

### Decrypt and Comparing part. `block_reader.c`

7. Loads the metadata saved.
8. Requests the session key corresponding to the session key id.
9. Read the `encrypted'i'.txt` and decrypt it with the requested session key.
10. Compare it with the read `plaintext'i'.txt`, and check if it's decrypted properly.

# Compile

For the rest of this document, we use $SST_ROOT for the root directory of [SST's main repository](https://github.com/iotauth/iotauth/).

```
$cd $SST_ROOT/entity/c/examples/file_block_encrypt_example
$mkdir build && cd build
$cmake ../
$make
```

# Example

- Turn on a Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a client1 terminal at `$SST_ROOT/entity/c/examples/file_block_encrypt_example/build`
- Turn on a client2 terminal at `$SST_ROOT/entity/c/examples/file_block_encrypt_example/build`

Execute

Auth Terminal 
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Client Terminal
`$ ./block_writer ../block_writer.config`
`$ ./block_reader ../block_reader.config`

### Example 2
Loading the saved key is also possible. `block_writer.c` saves the session key in `s_key_list.bin`. The next example does not request the session key by id, but loads the saved session key, and decrypts the file.
`$ ./block_reader_load_s_key_list`