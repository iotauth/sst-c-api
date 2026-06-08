# Heterogeneous C Client

This C example connects to the Node.js server in `entity/node/example_entities/heterogeneous_server.js`.

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
./heterogeneous_c_client ../heterogeneous_c_client.config
```

Optional custom message:

```bash
./heterogeneous_c_client ../heterogeneous_c_client.config "hello from C"
```
