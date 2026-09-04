#!/bin/bash

# ==============================================================================
# Multi-host IR distance-bounding test, driven from this Mac over SSH:
#   Initiator -> pi42@pi42   (sends the sync pulse and challenges)
#   Responder -> pi43@pi43   (waits for challenges, replies immediately)
#
# Both roles are the same ir_test.c binary; only the --role passed to it
# differs. See ir_com/ir_test.c and ir_com/run_ir_test.sh (the equivalent
# single-host launcher, for running directly on a Pi without SSH).
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
#   - ir_test.c (re)built on every run.
#
# SSH sessions to these hosts occasionally hang or drop a backgrounded
# process when the channel closes, so every remote call here is wrapped with
# a hard wall-clock timeout (macOS has no `timeout`, hence run_with_timeout
# below) and start_remote_and_verify() retries a few times before giving up.
# ==============================================================================

set -e

INITIATOR_HOST="pi42@pi42"
RESPONDER_HOST="pi43@pi43"
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
echo " Initiator: $INITIATOR_HOST   Responder: $RESPONDER_HOST"
echo "======================================================================"

# Always stop both remote processes on exit, whether the script succeeds,
# fails, or is interrupted.
cleanup() {
    echo ""
    echo "[Clean] Stopping Initiator ($INITIATOR_HOST) and Responder ($RESPONDER_HOST)..."
    [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
    # The [.] (instead of a plain .) keeps this pattern from matching the
    # literal text of the pkill/ssh invocation itself over the wire.
    ssh_to 15 "$INITIATOR_HOST" "sudo pkill -f '[.]/ir_test'" 2>/dev/null || true
    ssh_to 15 "$RESPONDER_HOST" "sudo pkill -f '[.]/ir_test'" 2>/dev/null || true
}
trap cleanup EXIT
# Explicit INT/TERM traps (not just EXIT) so this fires even when the shell
# would otherwise ignore SIGINT -- e.g. if this script itself is launched
# backgrounded (`... &`), bash disables SIGINT for it by default.
trap 'exit 130' INT TERM

# Starts a background process on a remote host and verifies (via pgrep) that
# it's still running a few seconds later, retrying a couple of times.
start_remote_and_verify() {
    local host="$1" start_cmd="$2" pgrep_pattern="$3" log_path="$4" label="$5"
    for attempt in 1 2 3; do
        ssh_to 15 "$host" "rm -f $log_path; $start_cmd" || true
        sleep 3
        # pgrep_pattern must be pre-bracketed (e.g. "[.]/ir_test") so it
        # doesn't match the literal text of this pgrep invocation itself.
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
echo "[1/3] Building ir_test on $INITIATOR_HOST and $RESPONDER_HOST..."
BUILD_CMD="cd $IR_DIR && gcc -O2 -Wall -pthread -o ir_test ir_test.c -lpigpio -lrt -lm"
ssh_to 60 "$INITIATOR_HOST" "$BUILD_CMD"
ssh_to 60 "$RESPONDER_HOST" "$BUILD_CMD"

echo ""
echo "[2/3] Starting Responder on $RESPONDER_HOST..."
ssh_to 15 "$RESPONDER_HOST" "sudo pkill -f '[.]/ir_test' 2>/dev/null" || true
start_remote_and_verify "$RESPONDER_HOST" \
    "cd $IR_DIR && setsid nohup sudo ./ir_test --role responder > /tmp/ir_test_responder.log 2>&1 < /dev/null &" \
    "[.]/ir_test" "/tmp/ir_test_responder.log" "Responder" || exit 1

# Stream Responder's log live in this terminal, prefixed so it's distinguishable
# from Initiator's own output below. Killed in cleanup() on exit.
ssh -o BatchMode=yes -o ConnectTimeout=8 "$RESPONDER_HOST" "tail -n +1 -f /tmp/ir_test_responder.log" 2>/dev/null | LC_ALL=C sed -u 's/^/[Responder] /' &
TAIL_PID=$!

echo ""
echo "[3/3] Running Initiator on $INITIATOR_HOST..."
# stdbuf forces line-buffered stdout over the ssh pipe (glibc otherwise fully
# buffers non-tty output, so Initiator's log wouldn't show up until it exits).
ssh_to 15 "$INITIATOR_HOST" "sudo pkill -f '[.]/ir_test'" 2>/dev/null || true
ssh_to 60 "$INITIATOR_HOST" "cd $IR_DIR && stdbuf -oL -eL sudo ./ir_test --role initiator" 2>&1 | LC_ALL=C sed -u 's/^/[Initiator] /' || true

sleep 2
echo ""
echo "======================================================================"
echo " Responder Log ($RESPONDER_HOST):"
echo "======================================================================"
ssh_to 15 "$RESPONDER_HOST" "cat /tmp/ir_test_responder.log" || true
echo "======================================================================"
