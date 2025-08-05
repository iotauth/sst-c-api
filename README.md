# Overview
---
This is a repository for C API of **[SST (Secure Swarm Toolkit)](https://github.com/iotauth/iotauth)** as a submodule.

# Prerequisites

-   OpenSSL:
    SST uses the APIs from OpenSSL for encryption and decryption. OpenSSL 3.0 above is required to run SST.
    -   On Max OS X, OpenSSL can be installed using `brew install openssl`.
    -   Following environment variables need to be set before running `make`. The exact variable values can be found from the output of `brew install openssl`.
    -   add two lines below by using `vi ~/.zshrc`
        -   `export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"`
        -   `export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"`

    - For Linux users, check [here](https://linuxhint.com/install-openssl-3-from-source/) for installation. 

# Code Hiearchy

c_common -> c_crypto -> c_secure_comm -> c_api -> entity_client, entity_server

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp; load_config --&uarr;

# C API

**SST_ctx_t \* init_SST()**

-   `init_SST()` is a function to load the config file, public and private keys, and store the distribution key.
-   It initializes important settings, at once.
-   Returns struct SST_ctx_t


**session_key_list_t \*init_empty_session_key_list(void)**
- `init_empty_session_key_list` initializes anempty session_key_list.
- Mallocs session_key_list_t and the session_key_t as much as the MAX_SESSION_KEY.

**session_key_list_t \* get_session_key()**

-   `get_session_key()` is a function to get secure session key from Auth.
-   Input is the struct config returned from the `init_SST()`, and the existing session key list. It can be NULL, if there were no list.
-   Returns struct session_key_list_t.

**SST_session_ctx_t *secure_connect_to_server(session_key_t *s_key, SST_ctx_t *ctx)**

-   `secure_connect_to_server()` is a function that establishes a secure connection with the entity server in the struct config.
-   Input is the session key received from `get_session_key()` and struct config returned from `load_config()`.
-   Returns struct SST_session_ctx_t

**SST_session_ctx_t *secure_connect_to_server_with_socket(session_key_t *s_key, int sock)**
- `secure_connect_to_server_with_socket` is a function that establishes a secure connection **using the connected socket with the target server**.
- Input is the session key received from `get_session_key()` and socket connected using `connect()`.

**SST_session_ctx_t \* server_secure_comm_setup()**

-   `server_secure_comm_setup()` is a function that the server continues to wait for the entity client and, if the client tries to connect, proceeds with a secure connection.
-   Input is the struct config.
-   Returns struct SST_session_ctx_t

**void \*receive_thread_read_one_each()**

-   Creates a thread to receive SECURE_COMM messages and prints the received messages.
-   Usage:

```
pthread_t thread;
pthread_create(&thread, NULL, &receive_thread_read_one_each, (void \*)session_ctx);
```

**int read_secure_message(unsigned char *buf, unsigned int buf_length, unsigned char *plaintext, SST_session_ctx_t *session_ctx)**

- `read_secure_message` checks the message header if it is a `SECURE_COMM_MSG`, and fills the buffer with the received decrypted message.
- Input is the pointer of the user declared buffer, and the given buffer's length (not the received message).
- Returns the length of the decrypted message.

**int send_secure_message()**

-   `send_secure_message()` is a function that sends a message with secure communication to the server by encrypting it with the session key.
- It recursively `write()`s until it sends the total message length.
- Input includes message, length of message, and session_ctx struct.
- Returns the bytes written if success, and -1 if failure.

The four functions below are for encrypting and decrypting buffers with the session key.

**int encrypt_buf_with_session_key()**
**int decrypt_buf_with_session_key()**
- These functions encrypt/decrypt the given plaintext/ciphertext with the given session key.
- It mallocs a buffer for the encrypted/decrypted result, and returns the double pointer of the encrypted/decrypted buffer.
- Returns 0 if success, 1 if failure.

**int encrypt_buf_with_session_key_without_malloc()**
**int decrypt_buf_with_session_key_without_malloc()**
- These two functions encrypt/decrypt the given plaintext/ciphertext with the given session key.
- Unlike the function above, they do not allocate memory, the user should provide the buffer with enough length.
- Returns 0 if success, 1 if failure.

The four functions below are for saving and the `session_key_list_t`,
**int save_session_key_list()**
**int load_session_key_list()**
- These two functions save/load the `session_key_list` to the `session_key_list_t` pointer.
- Before loading, `init_empty_session_key_list()` can be used to provide an empty session key list.
- Input includes the `session_key_list` to save/load, abd the file_path to save/load.

**int save_session_key_list_with_password()**
**int load_session_key_list_with_password()**
- These functions additionally get a password and salt as a `char *`, to encrypt/decrypt the `session_key_list`. 


**void free_session_key_list_t()**

-   `free_session_key_list_t()` is a function that frees the memory assigned to the config_t. It frees the memory assigned by the asymmetric key paths.

**void free_SST_ctx_t()**

-   `free_SST_ctx_t()` is a function that frees the memory assigned to the loaded SST_ctx. It recursively frees the memory assigned by SST_ctx.

# Compile

For the rest of this document, we use $SST_ROOT for the root directory of [SST's main repository](https://github.com/iotauth/iotauth/).


```
$cd $SST_ROOT/entity/c
$mkdir build && cd build
$cmake ../
$make
```

# Compile as Shared Library
The command below will install the shared library under `usr/local/lib/`, and `c_api.h` will be included in `usr/local/lib/include/sst-c-api/c_api.h`.

```
$mkdir build && cd build
$cmake ../
$make
$sudo make install
```

# Example

-   Turn on two different terminals at `$SST_ROOT/entity/c/examples/server_client_example/build`, and turn on Auth on the third terminal.

Execute

`$./entity_client ../c_client.config`

`$./entity_server ../c_server.config`

on each terminal

To test AES_128_CTR mode, with noHMAC when exchanging messages, execute

`$./entity_client ../c_computenode_CTR_noHMAC.config`

`$./entity_server ../c_compactionnode_CTR_noHMAC.config`

This will get all keys encrypted in AES_128_CTR mode, and send all messages in CTR mode, with no HMAC.

# For Developers

-   For C language indentation, we use the Google style.
    -   To enable the Google style indentation in VSCode, follow the instructions below. ([Source](https://stackoverflow.com/questions/46111834/format-curly-braces-on-same-line-in-c-vscode))
        1. Go Preferences -> Settings
        2. Search for `C_Cpp.clang_format_fallbackStyle`
        3. Click Edit, Copy to Settings
        4. Change from `"Visual Studio"` to `"{ BasedOnStyle: Google, IndentWidth: 4 }"`
    -   To format the code, follow instructions in this [page](https://code.visualstudio.com/docs/editor/codebasics#_formatting).

# TODOs

-   Implement an additional API function for extracting session key from cached session keys.

*Last updated on February 2, 2024*
