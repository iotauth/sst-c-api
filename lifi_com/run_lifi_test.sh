#!/bin/bash

# ==============================================================================
# Builds and runs lifi_test.c directly on this Raspberry Pi.
#
# Usage:
#   ./run_lifi_test.sh initiator [extra lifi_test options]
#   ./run_lifi_test.sh responder [extra lifi_test options]
#   ./run_lifi_test.sh loopback  [extra lifi_test options]
#
# Extra options are passed through. Defaults are the pi42 wiring (TX 23 /
# RX 22); pi43 needs --tx-gpio 22 --rx-gpio 23. --led-active-low for KS0016. Run initiator on one
# Pi and responder on the other; loopback needs one Pi with the LED aimed at
# its own sensor. Requires pigpio (the direct/embedded C library, header
# pigpio.h) already built and installed:
#   git clone https://github.com/joan2937/pigpio.git && cd pigpio && \
#   make && sudo make install
# It is not available as an apt package on current Raspberry Pi OS, and
# pigpio does not support the Pi 5.
# ==============================================================================

set -e

ROLE="$1"
if [ "$ROLE" != "initiator" ] && [ "$ROLE" != "responder" ] && [ "$ROLE" != "loopback" ]; then
    echo "Usage: $0 initiator|responder|loopback [lifi_test options]"
    exit 1
fi
shift

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building lifi_test..."
gcc -O2 -Wall -o lifi_test lifi_test.c -lpigpio -lrt -lpthread

echo "Running as $ROLE (Ctrl+C to stop)..."
exec sudo ./lifi_test --role "$ROLE" "$@"
