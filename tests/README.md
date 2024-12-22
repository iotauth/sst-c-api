# Tests for SST C API.
This directory is for testing functions in the SST C API.

`c_crypto_test.c` - Unit tests for functions in `c_crypto.c`.

`save_load_session_key_list_with_password_test.c` - Tests `save_session_key_list_with_password_test` and `load_session_key_list_with_password_test()`

# Instructions
## Turn on Auth
```
$ cd iotauth/auth/auth-server
$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

## Build tests
```
$ cd iotauth/entity/c/tests
$ mkdir build && cd build
$ cmake ../
$ make
```

## Execute tests
```
$ ./c_crypto_test
$ ./TEST ../test_configs/client.config
```