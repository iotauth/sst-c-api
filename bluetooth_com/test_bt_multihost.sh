#!/bin/bash

# ==============================================================================
# Multi-host Bluetooth LE ranging test, driven from this Mac over SSH:
#   Initiator -> pi42@pi42   (connects, sends PING rounds)
#   Responder -> pi43@pi43   (advertises, answers with PONG)
#
# Both roles are the same bt_test.c binary; see bluetooth_com/bt_test.c and
# bluetooth_com/run_bt_test.sh (the single-host launcher).
#
# Usage:
#   ./test_bt_multihost.sh [bt_test options]
#   e.g. ./test_bt_multihost.sh --rounds 50 --rssi-at-1m -55 --max-distance-m 1
# The same options go to both sides, so both judge with the same model.
#
# Assumes:
#   - Passwordless SSH and passwordless sudo on both hosts.
#   - ~/project/iotauth checked out on both hosts, with bt_test.c present.
#   - libbluetooth-dev installed on both hosts.
# ==============================================================================

set -eo pipefail

INITIATOR_HOST="pi42@pi42"
RESPONDER_HOST="pi43@pi43"
BT_DIR="project/iotauth/entity/c/bluetooth_com"
LOG="/tmp/bt_test_responder.log"
BT_ARGS="$*"

ssh_to() {
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$1" "$2" < /dev/null
}

cleanup() {
    ssh_to "$INITIATOR_HOST" "sudo pkill -f '[.]/bt_test'" 2>/dev/null || true
    ssh_to "$RESPONDER_HOST" "sudo pkill -f '[.]/bt_test'" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Bluetooth is soft-blocked by default on these Pis.
PREPARE="for r in /sys/class/rfkill/rfkill*; do [ \"\$(cat \$r/type)\" = bluetooth ] && echo 0 | sudo tee \$r/soft > /dev/null; done; bluetoothctl power on > /dev/null; cd $BT_DIR && gcc -O2 -Wall -Wextra -o bt_test bt_test.c bt_link.c -lbluetooth -lm"

echo "[1/3] Building bt_test on $INITIATOR_HOST and $RESPONDER_HOST..."
ssh_to "$INITIATOR_HOST" "$PREPARE"
ssh_to "$RESPONDER_HOST" "$PREPARE"
PEER=$(ssh_to "$RESPONDER_HOST" "hciconfig hci0 | awk '/BD Address/ {print \$3}'")
echo "Responder address: $PEER"

echo "[2/3] Starting Responder on $RESPONDER_HOST..."
cleanup
ssh_to "$RESPONDER_HOST" "cd $BT_DIR && rm -f $LOG && (setsid nohup sudo timeout 120 ./bt_test --role responder $BT_ARGS > $LOG 2>&1 < /dev/null &)"
sleep 2

echo "[3/3] Running Initiator on $INITIATOR_HOST..."
STATUS=0
ssh_to "$INITIATOR_HOST" "cd $BT_DIR && sudo timeout 120 ./bt_test --role initiator --peer $PEER $BT_ARGS" 2>&1 | LC_ALL=C sed -u 's/^/[Initiator] /' || STATUS=$?

sleep 1
ssh_to "$RESPONDER_HOST" "cat $LOG" | LC_ALL=C sed 's/^/[Responder] /'
exit $STATUS
