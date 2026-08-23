# Running the SST C++ API Tests

## Prerequisites

```bash
sudo apt install cmake g++ openssl
```

## 1. Build the library and unit tests

```bash
cd /home/lsmon/dev/crypto/sst-c-api/cpp
cmake --build build -j$(nproc)
```

This produces:
- `build/libsst-cpp-api.a` — static library
- `build/crypto_test` — crypto primitive unit tests
- `build/socket_test` — socket layer unit tests
- `build/api_test` — SST_API lifecycle & config tests

## 2. Recompile the AUTH_HELLO integration test

The integration test links against `spdlog`, which is not included in
the standard CMake target. Rebuild it manually after any code change:

```bash
cd /home/lsmon/dev/crypto/sst-c-api/cpp/build
g++ -std=c++17 -I../src \
    auth_connect_test.cpp \
    -L. -lsst-cpp-api \
    ./_deps/spdlog-build/libspdlog.a \
    -lssl -lcrypto -lpthread \
    -o auth_connect_test
```

## 3. Start the Auth server

The AUTH_HELLO integration test requires the Auth server running on
`127.0.0.1:21900`.

```bash
java -jar /home/lsmon/dev/crypto/iotauth/auth/auth-server/target/auth-server-jar-with-dependencies.jar \
    -p /home/lsmon/dev/crypto/iotauth/auth/properties/exampleAuth101.properties \
    --password=testpassword &
```

Or use the convenience script:

```bash
cd /home/lsmon/dev/crypto/sst-c-api/cpp
bash scripts/start_cpp.sh --password testpassword --auth-port 21900
```

## 4. Generate the entity config file

The config references a pre-registered entity (`Net1.Client`). Generate
the credentials and config:

```bash
# Copy Auth public key for entity verification
mkdir -p /home/lsmon/dev/crypto/iotauth/entity/auth_certs
cp /home/lsmon/dev/crypto/iotauth/auth/credentials/certs/Auth101EntityCert.pem \
   /home/lsmon/dev/crypto/iotauth/entity/auth_certs/

# Create the config file
cat > /home/lsmon/dev/crypto/sst-c-api/cpp/build/cpp_client.config << 'EOF'
name = Net1.Client
auth_id = 101
auth_pubkey_path = /home/lsmon/dev/crypto/iotauth/entity/auth_certs/Auth101EntityCert.pem
entity_privkey_path = /home/lsmon/dev/crypto/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem
auth_ip_addr = 127.0.0.1
auth_port_num = 21900
entity_server_ip_addr = 127.0.0.1
entity_server_port_num = 21100
session_key_enc_mode = 0
dist_key_enc_mode = 0
hmac_mode = 0
perm_dist_key_mode = 0
numkey = 5
purpose_index = 0
purpose[0] = default
purpose[1] = secure
EOF
```

## 5. Run the tests

### Unit tests (no auth-server needed)

```bash
cd /home/lsmon/dev/crypto/sst-c-api/cpp/build
./crypto_test
./socket_test
./api_test
```

### Integration test (requires running auth-server)

```bash
cd /home/lsmon/dev/crypto/sst-c-api/cpp/build
./auth_connect_test cpp_client.config
```

### Run everything at once

```bash
cd /home/lsmon/dev/crypto/sst-c-api/cpp/build && \
echo "=== Crypto Unit Tests ===" && ./crypto_test && \
echo "=== Socket Unit Tests ===" && ./socket_test && \
echo "=== API Unit Tests ===" && ./api_test && \
echo "=== AUTH_HELLO Integration Test ===" && ./auth_connect_test cpp_client.config
```
