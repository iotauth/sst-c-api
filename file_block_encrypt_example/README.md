# File block encrypt example

This is a simple example for RocksDB block encryption.

It randomly creates key_values (yet implemented in random buffers), append them into a block with a maximum size 32kbytes.
The leftover space is filled with zero padding.
Then the entire buffer is encrypted into a single block. The blocks are appended to a single file.

The detailed logic is as below.

1. Create random key_values, with a size between 56~144 bytes.
2. The key_values are appended until the total size is 32 kbytes.
3. When the next key_value does not fit to the maximum block size(32kybtes), the leftover size is filled with zero-paddings. 
4. The block is now 32kbytes, and it is encrypted with a session key.
5. 1~5 is repeated, making a single file. The blocks are appended to each other.
6. 5 is repeated, making three separate files, `encrypted'i'.txt`. Each file uses different session keys.

### Comparing part. 

7. To test if the encryption decryption worked prorperly, we make a `plaintext'i'.txt`, which is the blocks not encrypted.
8. Read the `encrypted'i'.txt` and decrypt it.
9. Compare it with the read `plaintext'i'.txt`, and check if it's decrypted properly.

# Compile

For the rest of this document, we use $SST_ROOT for the root directory of [SST's main repository](https://github.com/iotauth/iotauth/).

```
$cd $SST_ROOT/entity/c/file_block_encrypt_example
$mkdir build && cd build
$cmake ../
$make
```

# Example

- Turn on a Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a client terminal at `$SST_ROOT/entity/c/file_block_encrypt_example/build`

Execute

Auth Terminal 
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Client Terminal
`$ ./block_encrypt ../c_client.config`
