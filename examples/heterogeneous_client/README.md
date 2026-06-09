# Heterogeneous C Client

This C example connects to the existing Node.js server in the main `iotauth` repository:

```text
entity/node/example_entities/server.js
```

It is intentionally smaller than `entity_client.c` in `server_client_example`: it requests one session key, opens one secure connection, sends one message, and exits. That makes it suitable for a C-client-to-Node-server smoke test.

Use the full scenario README for generation and run order:

```text
$SST_ROOT/examples/heterogeneous/README.md
```

## Build

From this directory:

```bash
mkdir -p build
cd build
cmake ../
make
```

## Run

Start Auth and the Node.js server first. Then run from `build/`:

```bash
./heterogeneous_c_client ../../server_client_example/c_client.config
```

Optional custom message:

```bash
./heterogeneous_c_client ../../server_client_example/c_client.config "hello from C"
```
