# SST C server/client examples

Set `$SST_ROOT` to the absolute path of the main [SST repository](https://github.com/iotauth/iotauth), with this submodule checked out at `entity/c/`.
Generate credentials first with `./generateAll.sh` from `$SST_ROOT/examples`, and build Auth with `mvn clean install` from `$SST_ROOT/auth/auth-server`.

## Build

```sh
cd "$SST_ROOT/entity/c/examples/server_client_example"
cmake -S . -B build
cmake --build build
```

Use `-DCMAKE_BUILD_TYPE=Debug` during configuration to enable debug logging.
The examples build the C library from source; no system-wide installation is needed.

## Start Auth

In a separate terminal:

```sh
cd "$SST_ROOT/auth/auth-server"
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

Leave Auth running for the examples below.

## Example 1: secure communication

Start the server:

```sh
cd "$SST_ROOT/entity/c/examples/server_client_example/build"
./entity_server ../c_server.config
```

In another terminal, start the client:

```sh
cd "$SST_ROOT/entity/c/examples/server_client_example/build"
./entity_client ../c_client.config
```

Run from `build/`: relative credential paths in the configs are resolved from the process working directory. The client requests keys from Auth, completes the server handshake, and exchanges encrypted messages.

## Example 2: session keys by ID

From the same `build/` directory, run the client first to save the key IDs, then run the server to request those keys:

```sh
./threaded_get_target_id_client ../c_client.config
./threaded_get_target_id_server ../c_server.config
```

## Example 3: permanent distribution keys

The resource-constrained entities use permanent symmetric distribution keys instead of RSA credentials. Their graph entries must have `"usePermanentDistKey": true` when `generateAll.sh` runs. The checked-in `c_rc_client.config` and `c_rc_server.config` enable `PermanentDistKeyMode=on` and specify the distribution-key paths; verify these paths match the generated files, including filename case.

From `build/`, run the server and client in separate terminals:

```sh
./entity_server ../c_rc_server.config
```

```sh
./entity_client ../c_rc_client.config
```

## C++ counterpart

The [C++17 server/client examples](../../cpp/examples/server_client_example/README.md) use `sst::SST_API` and reuse the C configs. Follow their working-directory instructions. The C and C++ entities use the same wire protocol.
