# SST C API Examples

This directory contains several example programs that demonstrate how to use the `sst-c-api` with the main [SST (Secure Swarm Toolkit) repo](https://github.com/iotauth/iotauth).

For the rest of this document, we use `$SST_ROOT` for the root directory of SST’s main repository (`iotauth`), and this repository (`sst-c-api`) is assumed to be checked out as a submodule under `$SST_ROOT/entity/c`.

Each subdirectory here has its own `README.md` with detailed build and run instructions. This file gives a high-level overview and links into those examples.

---

## 1. Server–Client Example

A minimal example showing how to build a secure client–server application using SST:

- Uses Auth to distribute session keys between a client and a server.
- Demonstrates basic secure messaging over TCP channels.
- Shows how to configure entities via `.config` files and connect them through Auth.

For compilation and step-by-step run instructions, see:

- [`server_client_example/README.md`](./server_client_example/README.md)

---

## 2. IPFS Examples

Examples that integrate SST with [IPFS](https://ipfs.tech/) to realize a secure file-sharing workflow:

- `entity_uploader` encrypts a file with an SST session key and uploads it to IPFS.
- `entity_downloader` obtains the file hash and session key information from a file system manager, retrieves the encrypted file from IPFS, and decrypts it using SST.
- Includes both C and C++ entity implementations.

For compilation and step-by-step run instructions, see:

- Higher-level description in the main SST repo:  
  [`$SST_ROOT/examples/file_sharing/README.md`](https://github.com/iotauth/iotauth/tree/master/examples/file_sharing)
- C example: [`ipfs_examples/c/README.md`](./ipfs_examples/c/README.md)  
- C++ example: [`ipfs_examples/cpp/README.md`](./ipfs_examples/cpp/README.md)  

---

## 3. File Block Encrypt Example

An example focused on **block-based file encryption**, inspired by RocksDB-style block layouts:

- Random key–value pairs are packed into fixed-size (32 KB) blocks.
- Remaining space in a block is zero-padded.
- Each block is encrypted with a session key obtained via SST.
- Multiple encrypted blocks are written into files, along with metadata describing the session keys used.
- A separate reader:
  - Loads metadata.
  - Requests corresponding session keys.
  - Decrypts the blocks and verifies them against plaintext copies.

For compilation and step-by-step run instructions, see:

- [`file_block_encrypt_example/README.md`](./file_block_encrypt_example/README.md)

---

## 4. Scenario Example (SST Testbed)

A testbed to experiment attacks on SST.

- Uses Auth, example entities, and CSV-driven traffic patterns.
- Includes:
  1. **Basic messaging** between client and server.
  2. **Replay attack** scenarios (sequence number manipulation).
  3. **Denial of Service (DoS) attacks**:
     - To Auth via excessive session key requests (DoSK).
     - To server via repeated message sending (DoSM).
     - To server (and indirectly Auth) via repeated connection requests (DoSC).
  4. **Distributed DoS (DDoS)-style scenarios** with multiple clients.

For compilation steps, and detailed instructions for each scenario, see:

- [`scenario_example/README.md`](./scenario_example/README.md)

---

Each of these examples is designed to be run together with the Java Auth server in `$SST_ROOT/auth/auth-server/`. 
For deeper background on the architecture and example setups, refer to the corresponding `README.md` files in the main SST (`iotauth`) repository as well.