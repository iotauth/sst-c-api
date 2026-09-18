# SST C++ server/client example

C++ counterpart of [`examples/server_client_example`](../../../examples/server_client_example)
built on the SST C++ API (`cpp/src/api.hpp`). The programs speak the same
protocol as the C examples, so a C++ client can talk to a C server and vice
versa.

We use `$SST_ROOT` for the root directory of
[SST's main repository](https://github.com/iotauth/iotauth/).

# Compile

```
$ cd $SST_ROOT/entity/c/cpp/examples/server_client_example
$ mkdir build && cd build
$ cmake ../
$ make
```

# Example 1: secure server/client communication

- Turn on an Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a server terminal at `$SST_ROOT/entity/c/cpp/examples/server_client_example/build`
- Turn on a client terminal at `$SST_ROOT/entity/c/cpp/examples/server_client_example/build`

Auth terminal
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Server terminal
`$ ./entity_server ../c_server.config`

Client terminal
`$ ./entity_client ../c_client.config`

The client requests session keys from Auth, connects to the server twice
(once per session key) and both sides exchange encrypted messages.

# Example 2: session keys by ID from multiple threads

Gets multiple session keys, saves their IDs to metadata files, then requests
the keys by ID from three threads sharing one `sst::SST_API` instance.

- Turn on an Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a terminal at `$SST_ROOT/entity/c/cpp/examples/server_client_example/build`

Auth terminal
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Other terminal
`$ ./threaded_get_target_id_client ../c_client.config`
`$ ./threaded_get_target_id_server ../c_server.config`
