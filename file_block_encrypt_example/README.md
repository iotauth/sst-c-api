# File block encrypt example

This is a simple example for RocksDB.

The logic is as below.

1. User types the number of blocks they want.
2. A buffer is created with a random size, and random bytes.
3. The buffer gets encrypted with SST's session key.
4. The encrypted buffer is saved as a file named `encrypted.txt`, becoming a block.
5. The block's first index and length is saved as metadata.
6. Repeat 2~5 and append it to the `encrypted.txt` file, as much as the user's input.


### Comparing part. 

7. The user now selects the block's index they want to decrypt. 
8. The block is read from the file, using the metadata, and brings the encrypted buffer. 
9. The buffer gets decrypted. 
10. Compare the buffer with the plaintext that was also saved in a different file named `plaintext.txt`, using the same logic as above.

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
