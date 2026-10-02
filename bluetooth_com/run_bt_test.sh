#!/bin/bash

# ==============================================================================
# Builds and runs bt_test.c directly on this Raspberry Pi.
#
# Usage:
#   ./run_bt_test.sh responder [bt_test options]          # advertises, waits
#   ./run_bt_test.sh initiator PEER_BDADDR [options]      # connects to PEER
#
# Start the responder first on one Pi, then the initiator on the other with
# the responder's address (`hciconfig hci0` there prints it as "BD Address").
# Extra options are passed to bt_test (e.g. --rounds 50 --rssi-at-1m -55).
# Requires libbluetooth-dev; this unblocks and powers on Bluetooth, which is
# soft-blocked by default on these Pis.
# ==============================================================================

set -e

ROLE="$1"
if [ "$ROLE" = "responder" ]; then
    shift
    ARGS=(--role responder "$@")
elif [ "$ROLE" = "initiator" ] && [ -n "$2" ]; then
    PEER="$2"
    shift 2
    ARGS=(--role initiator --peer "$PEER" "$@")
else
    echo "Usage: $0 responder [options] | initiator PEER_BDADDR [options]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

for r in /sys/class/rfkill/rfkill*; do
    if [ "$(cat "$r/type")" = bluetooth ]; then
        echo 0 | sudo tee "$r/soft" > /dev/null
    fi
done
bluetoothctl power on > /dev/null

echo "Building bt_test..."
gcc -O2 -Wall -Wextra -o bt_test bt_test.c bt_link.c -lbluetooth -lm

echo "Running as $ROLE..."
exec sudo ./bt_test "${ARGS[@]}"
