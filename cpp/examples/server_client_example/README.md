# SST C++ server/client example

C++ counterpart of the C example in
[`examples/server_client_example`](../../../examples/server_client_example),
built on the SST C++ API (`cpp/src/api.hpp`). The programs speak the same
protocol as the C programs, so a C++ client can talk to a C server and vice
versa.

The example reuses the C example's config files (`c_server.config` and
`c_client.config`). The key paths in those files are relative to the current
working directory, so run the binaries from this directory (not from `build/`)
as shown below.

Below, `$SST_ROOT` is the root directory of
[SST's main repository](https://github.com/iotauth/iotauth/). Generate the
example credentials first (`examples/generateAll.sh`) and build the Auth
server (`auth/README.md`).

## Build

```
$ cd $SST_ROOT/entity/c/cpp/examples/server_client_example
$ mkdir build && cd build
$ cmake ../
$ make
$ cd ..
```

## Start Auth

In a terminal at `$SST_ROOT/auth/auth-server`:

```
$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

Keep it running for both examples below.

## Example 1: secure server/client communication

The client requests session keys from Auth, connects to the server twice
(once per session key) and both sides exchange encrypted messages.

In a terminal at `$SST_ROOT/entity/c/cpp/examples/server_client_example`:

```
$ ./build/entity_server ../../../examples/server_client_example/c_server.config
```

In another terminal at the same directory:

```
$ ./build/entity_client ../../../examples/server_client_example/c_client.config
```

Both programs print the messages they receive and exit when done.

## Example 2: session keys by ID from multiple threads

The client gets three session keys and saves their IDs to `s_key_id0.dat`,
`s_key_id1.dat` and `s_key_id2.dat`. The server then requests the keys by ID
from three threads sharing one `sst::SST_API` instance.

In a terminal at `$SST_ROOT/entity/c/cpp/examples/server_client_example`:

```
$ ./build/threaded_get_target_id_client ../../../examples/server_client_example/c_client.config
$ ./build/threaded_get_target_id_server ../../../examples/server_client_example/c_server.config
```
