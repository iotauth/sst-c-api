# Tests for SST C API
This directory includes unit tests and integration tests for the SST C API.

## Unit Tests

- `c_crypto_test.c`: Unit tests for functions in `c_crypto.c`.

## Integration Tests with Auth

- `save_load_session_key_list_with_password_test.c`: Tests `save_session_key_list_with_password_test()` and `load_session_key_list_with_password_test()`.

- `encrypt_buf_with_session_key_without_malloc_execution_time_test.c` : Tests the time taken from `encrypt_buf_with_session_key_without_malloc()` and `decrypt_buf_with_session_key_without_malloc()`.

- `multi_thread_get_session_key_test.c` : Tests `get_session_key()` called simultaneously by multiple threads. This test fails.

# Test Instructions

We use $IOTAUTH for the root directory of `iotauth` repo.

## Generate example Auths and entities (If you haven't already done so)
```
$ cd $IOTAUTH/examples
$ ./generateAll.sh
```

## Turn on Auth (Only Applicable to Integration Tests)
```
$ cd $IOTAUTH/auth/auth-server
```
Run `make` if you have not built Auth jar before.
```
$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

## Build tests (For Both Unit Tests and Integration Tests)
```
$ cd $IOTAUTH/entity/c/tests
$ mkdir build && cd build
$ cmake ../
$ make
```

## Execute Unit Tests
```
$ ./c_crypto_test
```

## Execute Integration Tests
$TEST is one of the integration tests above.
```
$ ./$TEST ../test_configs/client.config
```
