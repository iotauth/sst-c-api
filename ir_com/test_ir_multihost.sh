#!/bin/bash

# ==============================================================================
# Multi-host IR distance-bounding test:
#   Sender (A / Verifier)   -> pi42@pi42
#   Receiver (B / Prover)   -> pi43@pi43
#
# Usage:
#   ./test_ir_multihost.sh
#
# Assumes:
#   - Passwordless SSH and passwordless sudo (pigpio needs root for direct
#     GPIO access) to both hosts.
#   - ~/project/iotauth checked out on the physical branch on both hosts.
#   - pigpio (the direct/embedded C library, header pigpio.h) already built
#     and installed on both hosts -- e.g. via:
#       git clone https://github.com/joan2937/pigpio.git && cd pigpio && \
#       make && sudo make install
#     It is not available as an apt package on current Raspberry Pi OS
#     (Debian trixie only ships the pigpiod client/daemon packages, which
#     use a different API). This script does not install pigpio itself.
#   - ir_sender.c/ir_receiver.c (re)built on every run.
#
# SSH sessions to these hosts occasionally hang or drop a backgrounded
# process when the channel closes, so every remote call here is wrapped with
# a hard wall-clock timeout (macOS has no `timeout`, hence run_with_timeout
# below) and start_remote_and_verify() retries a few times before giving up.
# ==============================================================================

set -e

SENDER_HOST="pi42@pi42"
RECEIVER_HOST="pi43@pi43"
REMOTE_REPO="project/iotauth"
IR_DIR="$REMOTE_REPO/entity/c/ir_com"
TAIL_PID=""

# Runs a command with a hard wall-clock timeout. Portable bash implementation
# since macOS has no `timeout`/`gtimeout` by default. Returns the wrapped
# command's exit status, or 124 if it had to be killed for running too long.
run_with_timeout() {
    local secs="$1"; shift
    "$@" &
    local cmd_pid=$!
    ( sleep "$secs" 2>/dev/null && kill -9 "$cmd_pid" 2>/dev/null ) &
    local watchdog_pid=$!
    local status=0
    wait "$cmd_pid" 2>/dev/null || status=$?
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    return $status
}

ssh_to() {
    local timeout_secs="$1" host="$2" cmd="$3"
    run_with_timeout "$timeout_secs" ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "$cmd"
}

echo "======================================================================"
echo " Sender (A/Verifier): $SENDER_HOST   Receiver (B/Prover): $RECEIVER_HOST"
echo "======================================================================"

# Always stop both remote processes on exit, whether the script succeeds,
# fails, or is interrupted.
cleanup() {
    echo ""
    echo "[Clean] Stopping Sender ($SENDER_HOST) and Receiver ($RECEIVER_HOST)..."
    [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
    ssh_to 15 "$SENDER_HOST" "sudo pkill -f './ir_sender'" 2>/dev/null || true
    ssh_to 15 "$RECEIVER_HOST" "sudo pkill -f './ir_receiver'" 2>/dev/null || true
}
trap cleanup EXIT

# Starts a background process on a remote host and verifies (via pgrep) that
# it's still running a few seconds later, retrying a couple of times.
start_remote_and_verify() {
    local host="$1" start_cmd="$2" pgrep_pattern="$3" log_path="$4" label="$5"
    for attempt in 1 2 3; do
        ssh_to 15 "$host" "rm -f $log_path; $start_cmd" || true
        sleep 3
        if ssh_to 15 "$host" "pgrep -f '$pgrep_pattern' > /dev/null"; then
            return 0
        fi
        echo "[$label] did not survive on attempt $attempt/3, retrying..."
    done
    echo "[Error] $label failed to start after 3 attempts! Log output:"
    ssh_to 15 "$host" "cat $log_path" 2>/dev/null || true
    return 1
}

echo ""
echo "[1/3] Building ir_sender on $SENDER_HOST and ir_receiver on $RECEIVER_HOST..."
BUILD_CMD="cd $IR_DIR && gcc -O2 -Wall -pthread -o ir_sender ir_sender.c -lpigpio -lrt -lm && gcc -O2 -Wall -pthread -o ir_receiver ir_receiver.c -lpigpio -lrt -lm"
ssh_to 60 "$SENDER_HOST" "$BUILD_CMD"
ssh_to 60 "$RECEIVER_HOST" "$BUILD_CMD"

echo ""
echo "[2/3] Starting Receiver on $RECEIVER_HOST (B/Prover)..."
ssh_to 15 "$RECEIVER_HOST" "sudo pkill -f './ir_receiver' 2>/dev/null" || true
start_remote_and_verify "$RECEIVER_HOST" \
    "cd $IR_DIR && setsid nohup sudo ./ir_receiver > /tmp/ir_receiver_test.log 2>&1 < /dev/null &" \
    "./ir_receiver" "/tmp/ir_receiver_test.log" "Receiver" || exit 1

# Stream Receiver's log live in this terminal, prefixed so it's distinguishable
# from Sender's own output below. Killed in cleanup() on exit.
ssh -o BatchMode=yes -o ConnectTimeout=8 "$RECEIVER_HOST" "tail -n +1 -f /tmp/ir_receiver_test.log" 2>/dev/null | LC_ALL=C sed -u 's/^/[Receiver] /' &
TAIL_PID=$!

echo ""
echo "[3/3] Running Sender on $SENDER_HOST (A/Verifier)..."
# stdbuf forces line-buffered stdout over the ssh pipe (glibc otherwise fully
# buffers non-tty output, so Sender's log wouldn't show up until it exits).
ssh_to 60 "$SENDER_HOST" "cd $IR_DIR && stdbuf -oL -eL sudo ./ir_sender" 2>&1 | LC_ALL=C sed -u 's/^/[Sender] /' || true

sleep 2
echo ""
echo "======================================================================"
echo " Receiver Log ($RECEIVER_HOST):"
echo "======================================================================"
ssh_to 15 "$RECEIVER_HOST" "cat /tmp/ir_receiver_test.log" || true
echo "======================================================================"
