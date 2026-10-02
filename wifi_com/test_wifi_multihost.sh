#!/bin/bash

# ==============================================================================
# Mutual Wi-Fi RSSI ranging test between pi42 and pi43, driven from this Mac
# over SSH, independent of SST.
#
# Only a station can read the RSSI of its link (the AP side's firmware
# reports none), so this runs two phases with the roles swapped, each over a
# fresh direct link from wifi_link.sh next to the Pis' own wlan0:
#   phase 1: pi43 AP (uap0), pi42 station (wlan1) -> pi42 measures pi43
#   phase 2: pi42 AP (uap0), pi43 station (wlan1) -> pi43 measures pi42
# Each Pi judges only its own measurement. The link is always removed
# between phases and on exit (and by wifi_link.sh's own timer otherwise).
#
# The test link must share each Pi's wlan0 channel, so both wlan0s must be
# on the same campus AP. Roaming is host-driven on these Pis (brcmfmac
# roamoff=1), so pin it in the saved connection, on each Pi:
#   nmcli con modify asu 802-11-wireless.bssid <BSSID> && nmcli con up asu
# and undo it afterwards with an empty bssid. ("nmcli con up asu ap <BSSID>"
# alone is only a hint and does not stop later roaming.)
#
# Usage:
#   ./test_wifi_multihost.sh [wifi_test options]
#   e.g. ./test_wifi_multihost.sh --rounds 50 --rssi-at-1m -35 --max-distance-m 1
# The same options go to both stations, so both judge with the same model.
#
# Assumes passwordless SSH and sudo on both hosts, and ~/project/iotauth on
# both with this directory present.
# ==============================================================================

set -eo pipefail

PI42="pi42@pi42"
PI43="pi43@pi43"
WIFI_DIR="project/iotauth/entity/c/wifi_com"
AP_LOG="/tmp/wifi_test_ap.log"
LINK_MINUTES=10
TEST_ARGS="$*"
SUMMARY=""
STATUS=0

ssh_to() {
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$1" "$2" < /dev/null
}

link_down() {
    for h in "$PI42" "$PI43"; do
        ssh_to "$h" "pkill -f '[.]/wifi_test' 2>/dev/null; $WIFI_DIR/wifi_link.sh down" > /dev/null 2>&1 || true
    done
}
trap link_down EXIT
trap 'exit 130' INT TERM

echo "[1/3] Preparing both Pis (hostapd, wifi_test build)..."
for h in "$PI42" "$PI43"; do
    # The hostapd package ships its service masked here; it is only ever
    # started by wifi_link.sh, on uap0.
    ssh_to "$h" "dpkg -s hostapd > /dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q hostapd > /dev/null; cd $WIFI_DIR && chmod +x wifi_link.sh && gcc -O2 -Wall -Wextra -o wifi_test wifi_test.c -lm"
done
link_down

wlan0_channel() {
    ssh_to "$1" "/usr/sbin/iw dev wlan0 info | awk '/channel/ {print \$2}'" 2>/dev/null || true
}

# The test link shares wlan0's channel, so both wlan0s must be on one
# channel; see the header for pinning them.
align_channels() {
    local c42 c43
    c42=$(wlan0_channel "$PI42"); c43=$(wlan0_channel "$PI43")
    if [ -n "$c42" ] && [ "$c42" = "$c43" ]; then
        echo "Both wlan0 on channel $c42."
        return 0
    fi
    echo "wlan0 channels differ (pi42=$c42 pi43=$c43); pin both to one AP first."
    return 1
}

# Runs one phase: $1 opens the AP, $2 joins and measures. Returns 1 only
# when the link could not be set up (nothing was measured), so it can be
# retried.
phase() {
    local ap="$1" sta="$2" label="$3" rc=0
    echo ""
    echo "=== $label: AP ${ap#*@}, station ${sta#*@} (measures) ==="
    if ! align_channels || ! ssh_to "$ap" "$WIFI_DIR/wifi_link.sh ap $LINK_MINUTES" ||
        ! ssh_to "$sta" "$WIFI_DIR/wifi_link.sh sta $LINK_MINUTES"; then
        link_down
        return 1
    fi
    ssh_to "$ap" "cd $WIFI_DIR && rm -f $AP_LOG && (setsid nohup timeout 120 ./wifi_test --role ap > $AP_LOG 2>&1 < /dev/null &)"
    sleep 1
    local out
    out=$(ssh_to "$sta" "cd $WIFI_DIR && timeout 120 ./wifi_test --role station --peer 192.168.77.1 $TEST_ARGS" 2>&1) || rc=$?
    echo "$out" | sed "s/^/[${sta#*@} station] /"
    sleep 1
    ssh_to "$ap" "cat $AP_LOG" | sed "s/^/[${ap#*@} ap] /"
    local result
    result=$(echo "$out" | grep "WIFI RANGE: local" || echo "no result (exit $rc)")
    SUMMARY="$SUMMARY  [${sta#*@}] measured ${ap#*@}: ${result#*WIFI RANGE: local }"$'\n'
    if ! echo "$out" | grep -q "WIFI RANGE: local .*result=PASS"; then STATUS=1; fi
    link_down
}

run_phase() {
    local attempt
    for attempt in 1 2 3; do
        phase "$@" && return 0
        echo "[$3] link setup failed (attempt $attempt/3)."
    done
    SUMMARY="$SUMMARY  [${2#*@}] measured ${1#*@}: no result (link setup failed)"$'\n'
    STATUS=1
}

echo "[2/3] Phase 1..."
run_phase "$PI43" "$PI42" "Phase 1"
echo "[3/3] Phase 2..."
run_phase "$PI42" "$PI43" "Phase 2"

echo ""
echo "======================================================================"
echo " Wi-Fi RSSI results (each Pi's own measurement):"
printf '%s' "$SUMMARY"
echo " overall: $([ "$STATUS" = 0 ] && echo PASS || echo FAIL)"
echo "======================================================================"
exit "$STATUS"
