#!/bin/bash

# ==============================================================================
# Builds and runs ir_test.c directly on this Raspberry Pi.
#
# Usage:
#   ./run_ir_test.sh initiator    # sends the sync pulse and challenges
#   ./run_ir_test.sh responder    # waits for challenges and replies
#
# Run this once on each of the two Pis wired for the IR test -- one as
# initiator, the other as responder. Requires pigpio (the direct/embedded C
# library, header pigpio.h) already built and installed:
#   git clone https://github.com/joan2937/pigpio.git && cd pigpio && \
#   make && sudo make install
# It is not available as an apt package on current Raspberry Pi OS.
# ==============================================================================

set -e

ROLE="$1"
if [ "$ROLE" != "initiator" ] && [ "$ROLE" != "responder" ]; then
    echo "Usage: $0 initiator|responder"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building ir_test..."
gcc -O2 -Wall -pthread -o ir_test ir_test.c -lpigpio -lrt -lm

echo "Running as $ROLE (Ctrl+C to stop)..."
exec sudo ./ir_test --role "$ROLE"
