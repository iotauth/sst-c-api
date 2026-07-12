#!/bin/bash

# =============================================================================
# start_cpp.sh — Agent to build and connect sst-cpp-api to the Auth server
#
# This script:
#   1. Reads sst-c-api/cpp/README.md to understand the project
#   2. Builds sst-cpp-api with CMake
#   3. Generates a configuration file for the C++ entity
#   4. Connects to the Auth server (using the first agent's infrastructure)
#   5. Runs integration tests
#
# Usage: ./start_cpp.sh [options]
#
# Options:
#   --password <pass>   Password for Auth (default: 1234)
#   --auth-host <host>  Auth server host (default: 127.0.0.1)
#   --auth-port <port>  Auth server TCP port (default: 21900)
#   --entity-name <name>  Entity name (default: cpp_client)
#   --restart           Clean and rebuild
#   --build-only        Only build, do not connect
#   --no-build          Skip CMake build (use existing library)
#   --test-only         Only run tests, no Auth connection
#   --stop              Stop any running Auth server
#   -h, --help          Show this help
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CPP_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IOTAUTH_ROOT="$(cd "$CPP_ROOT/../iotauth" && pwd)"
AUTH_SERVER_DIR="$IOTAUTH_ROOT/auth/auth-server"
AUTH_JAR="$AUTH_SERVER_DIR/target/auth-server-jar-with-dependencies.jar"
AUTH_PROPS="$IOTAUTH_ROOT/auth/properties/exampleAuth101.properties"
AUTH_LOG="$SCRIPT_DIR/auth.log"
AUTH_PID_FILE="$SCRIPT_DIR/auth.pid"

# --- Defaults ---
AUTH_PASSWORD="${AUTH_PASSWORD:-testpassword}"
AUTH_HOST="127.0.0.1"
AUTH_PORT=21900
ENTITY_NAME="cpp_client"
RESTART=false
BUILD_ONLY=false
NO_BUILD=false
TEST_ONLY=false
STOP_ONLY=false

# --- Helpers ---

log() {
	echo "[$(date '+%H:%M:%S')] [CPP] $*"
}

error() {
	echo "[$(date '+%H:%M:%S')] [CPP] ERROR: $*" >&2
}

cleanup() {
	log "Cleaning up..."
	local pid
	pid="$(cat "$AUTH_PID_FILE" 2>/dev/null || true)"
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		log "Stopping Auth server (PID $pid)..."
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -f "$AUTH_PID_FILE"
}

trap cleanup EXIT INT TERM

show_help() {
	cat <<EOF
Usage: $(basename "$0") [options]

Build and connect sst-cpp-api to the Auth server (first agent).

Options:
  --password <pass>       Password for Auth (default: 1234)
  --auth-host <host>      Auth server host (default: 127.0.0.1)
  --auth-port <port>      Auth server TCP port (default: 21900)
  --entity-name <name>    Entity name (default: cpp_client)
  --restart               Clean and rebuild
  --build-only            Only build, do not connect to Auth
  --no-build              Skip CMake build (use existing library)
  --test-only             Only run crypto tests (no Auth connection)
  --stop                  Stop any running Auth server
  -h, --help              Show this help

Example:
  ./start_cpp.sh --password 1234 --auth-port 21900
  ./start_cpp.sh --build-only
  ./start_cpp.sh --test-only
  ./start_cpp.sh --stop
EOF
}

# --- Argument parsing ---

while [[ $# -gt 0 ]]; do
	case "$1" in
		--password) shift; AUTH_PASSWORD="$1" ;;
		--auth-host) shift; AUTH_HOST="$1" ;;
		--auth-port) shift; AUTH_PORT="$1" ;;
		--entity-name) shift; ENTITY_NAME="$1" ;;
		--restart) RESTART=true ;;
		--build-only) BUILD_ONLY=true ;;
		--no-build) NO_BUILD=true ;;
		--test-only) TEST_ONLY=true ;;
		--stop) STOP_ONLY=true ;;
		-h|--help) show_help; exit 0 ;;
		*) error "Unknown option: $1"; show_help; exit 1 ;;
	esac
	shift
done

# --- Stop existing Auth if requested ---

if [[ "$STOP_ONLY" == true ]]; then
	log "Looking for running Auth server on port $AUTH_PORT..."
	pid="$(lsof -tiTCP:"$AUTH_PORT" -sTCP:LISTEN 2>/dev/null || true)"
	if [[ -n "$pid" ]]; then
		log "Stopping Auth server (PID $pid)..."
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
		log "Auth server stopped."
	else
		log "No Auth server found on port $AUTH_PORT."
	fi
	exit 0
fi

# --- Stop any existing Auth server ---

pid="$(lsof -tiTCP:"$AUTH_PORT" -sTCP:LISTEN 2>/dev/null || true)"
if [[ -n "$pid" ]]; then
	log "Auth server already running on port $AUTH_PORT (PID $pid). Stopping..."
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	sleep 1
fi

# --- Validate prerequisites ---

log "Checking prerequisites..."
for cmd in cmake g++ openssl; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		error "Missing required command: $cmd"
		exit 1
	fi
done
log "All prerequisites met."

# --- Step 1: Generate credentials (if needed) ---

log "Step 1: Checking credentials..."
if [[ ! -f "$IOTAUTH_ROOT/auth/credentials/keystores/Auth101Entity.pfx" ]]; then
	error "Auth101Entity.pfx not found. Run the auth-server agent first."
	exit 1
fi
if [[ ! -f "$AUTH_JAR" ]]; then
	error "Auth server JAR not found: $AUTH_JAR. Build the auth-server first."
	exit 1
fi
log "Credentials verified."

# --- Step 2: Build sst-cpp-api ---

if [[ "$NO_BUILD" == false ]]; then
	log "Step 2: Building sst-cpp-api with CMake..."

	BUILD_DIR="$CPP_ROOT/build"
	if [[ "$RESTART" == true ]]; then
		log "Cleaning previous build..."
		rm -rf "$BUILD_DIR"
	fi

	mkdir -p "$BUILD_DIR"
	(
		cd "$BUILD_DIR"
		cmake -S "$CPP_ROOT" -B . -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -5
		cmake --build . -j"$(nproc)" 2>&1 | tail -10
	)

	if [[ ! -f "$BUILD_DIR/libsst-cpp-api.a" ]]; then
		error "Build failed: library not found at $BUILD_DIR/libsst-cpp-api.a"
		exit 1
	fi
	log "sst-cpp-api built successfully."

	if [[ ! -x "$BUILD_DIR/crypto_test" ]] || [[ ! -x "$BUILD_DIR/api_test" ]]; then
		error "Build failed: test executables not found"
		exit 1
	fi
	log "Test executables built: crypto_test, api_test"
else
	log "Step 2: Skipping CMake build (--no-build)."
fi

# --- Step 3: Run crypto tests (no Auth needed) ---

if [[ "$TEST_ONLY" == false ]]; then
	log "Step 3: Running crypto unit tests..."
	(
		cd "$BUILD_DIR"
		./crypto_test 2>&1
	)
	if [[ $? -eq 0 ]]; then
		log "Crypto tests passed."
	else
		error "Crypto tests failed!"
		exit 1
	fi
fi

# --- Step 4: Generate config for Auth connection ---

if [[ "$TEST_ONLY" == true ]]; then
	log "Step 4: Skipping Auth connection (--test-only)."
elif [[ "$BUILD_ONLY" == true ]]; then
	log "Step 4: Build-only mode. sst-cpp-api ready."
	log "  Library: $BUILD_DIR/libsst-cpp-api.a"
	log "  Tests:   $BUILD_DIR/crypto_test, $BUILD_DIR/api_test"
	log ""
	log "To connect to Auth, start the auth-server first, then run:"
	log "  $0 --password $AUTH_PASSWORD --auth-port $AUTH_PORT"
	exit 0
fi

# --- Step 5: Start Auth server (first agent) ---

log "Step 5: Starting Auth server..."
cd "$AUTH_SERVER_DIR"

nohup java -jar "$AUTH_JAR" -p "$AUTH_PROPS" --password="$AUTH_PASSWORD" \
	> "$AUTH_LOG" 2>&1 &
AUTH_PID=$!
echo "$AUTH_PID" > "$AUTH_PID_FILE"

log "Auth server started (PID $AUTH_PID). Waiting for readiness..."

READY=false
for i in $(seq 1 30); do
	if grep -q "Enter command" "$AUTH_LOG" 2>/dev/null; then
		READY=true
		break
	fi
	if ! kill -0 "$AUTH_PID" 2>/dev/null; then
		error "Auth server exited prematurely."
		log "--- Last log lines ---"
		tail -20 "$AUTH_LOG"
		exit 1
	fi
	sleep 1
done

if [[ "$READY" != true ]]; then
	error "Auth server failed to start within 30 seconds."
	log "--- Last log lines ---"
	tail -30 "$AUTH_LOG"
	exit 1
fi

log "Auth server is ready on port $AUTH_PORT."

# --- Step 6: Generate entity config ---

log "Step 6: Generating configuration for $ENTITY_NAME..."

# Find entity private key (create a test one if needed)
ENTITY_KEY_DIR="$IOTAUTH_ROOT/entity/credentials/keys/$ENTITY_NAME"
AUTH_CERT_DIR="$IOTAUTH_ROOT/entity/auth_certs"

# Create entity credentials if they don't exist
if [[ ! -d "$ENTITY_KEY_DIR" ]]; then
	log "Creating entity credentials for $ENTITY_NAME..."
	mkdir -p "$ENTITY_KEY_DIR"
	mkdir -p "$AUTH_CERT_DIR"

	# Generate RSA key pair for the entity
	openssl genrsa -out "$ENTITY_KEY_DIR/${ENTITY_NAME}.pem" 2048 2>/dev/null
	log "Entity key generated."

	# Copy Auth101 public key for authentication
	if [[ -f "$IOTAUTH_ROOT/auth/credentials/certs/Auth101EntityCert.pem" ]]; then
		cp "$IOTAUTH_ROOT/auth/credentials/certs/Auth101EntityCert.pem" \
		   "$AUTH_CERT_DIR/Auth101EntityCert.pem"
		log "Auth public key copied."
	fi
fi

# Generate entity config
CONFIG_FILE="$BUILD_DIR/${ENTITY_NAME}.config"
cat > "$CONFIG_FILE" <<EOF
# SST C++ API Configuration
# Generated by start_cpp.sh

name = $ENTITY_NAME
auth_id = 101
auth_pubkey_path = $AUTH_CERT_DIR/Auth101EntityCert.pem
entity_privkey_path = $ENTITY_KEY_DIR/${ENTITY_NAME}.pem
auth_ip_addr = $AUTH_HOST
auth_port_num = $AUTH_PORT
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

log "Config generated: $CONFIG_FILE"

# --- Step 7: Run API integration test (connects to Auth) ---

log "Step 7: Running API integration test (connecting to Auth)..."

# Create a small test program that exercises the Auth handshake
TEST_APP="$BUILD_DIR/auth_connect_test"
cat > "$BUILD_DIR/auth_connect_test.cpp" <<'CPPEOF'
/**
 * @file auth_connect_test.cpp
 * @brief Integration test: connects to Auth server via sst-cpp-api
 *
 * Tests:
 * 1. SST_API initialization with valid config
 * 2. Auth hello handshake
 * 3. Session key retrieval
 * 4. Connection cleanup
 */

#include "../src/api.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using sst::SST_API;
using sst::SST_Exception;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    std::string config_path = argv[1];
    std::cout << "=== SST C++ API Auth Connection Test ===" << std::endl;
    std::cout << "Config: " << config_path << std::endl;
    std::cout << std::endl;

    try {
        // Step 1: Initialize SST_API
        std::cout << "[1/4] Initializing SST_API..." << std::endl;
        SST_API api(config_path);
        std::cout << "  SST_API initialized successfully." << std::endl;

        // Step 2: Perform AUTH_HELLO
        std::cout << "[2/4] Performing AUTH_HELLO handshake..." << std::endl;
        api.auth_hello();
        std::cout << "  AUTH_HELLO completed successfully." << std::endl;

        // Step 3: Retrieve session keys
        std::cout << "[3/4] Requesting session keys..." << std::endl;
        auto keys = api.get_session_keys("default");
        std::cout << "  Retrieved " << keys.size() << " session key(s)." << std::endl;

        for (size_t i = 0; i < keys.size(); ++i) {
            std::cout << "    Key " << i << " ID: [";
            for (size_t j = 0; j < keys[i].id.size() && j < 8; ++j) {
                printf("%02x", keys[i].id[j]);
            }
            std::cout << "]" << std::endl;
        }

        // Step 4: Cleanup
        std::cout << "[4/4] Cleaning up..." << std::endl;
        // SST_API destructor handles cleanup

        std::cout << std::endl;
        std::cout << "=== Auth connection test PASSED ===" << std::endl;
        return 0;

    } catch (const SST_Exception& e) {
        std::cerr << std::endl;
        std::cerr << "=== Auth connection test FAILED ===" << std::endl;
        std::cerr << "SST_Exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << std::endl;
        std::cerr << "=== Auth connection test FAILED ===" << std::endl;
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}
CPPEOF

cmake -S "$BUILD_DIR" -B "$BUILD_DIR/test_build" \
    -DCMAKE_CXX_STANDARD=17 2>/dev/null || true

(
    cd "$BUILD_DIR"
    g++ -std=c++17 -I"$CPP_ROOT/src" \
        auth_connect_test.cpp \
        -L. -lsst-cpp-api \
        -lssl -lcrypto \
        -lpthread \
        -o auth_connect_test 2>&1
)

if [[ $? -eq 0 ]]; then
    log "Test application compiled."
    log "Running Auth connection test..."
    echo ""
    ./auth_connect_test "$CONFIG_FILE"
else
    error "Failed to compile Auth connection test."
    exit 1
fi

# --- Cleanup ---

log ""
log "All tests completed."
log "Auth server stopped."