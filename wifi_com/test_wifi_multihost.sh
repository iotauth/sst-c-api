#!/bin/bash

# ==============================================================================
# Mutual Wi-Fi RSSI ranging test between pi42 and pi43, driven from this Mac
# over SSH, independent of SST.
#
# Brings up a direct link on each Pi's USB Wi-Fi dongle with wifi_link.sh
# (pi43 opens the AP, pi42 joins it), next to the Pis' own wlan0, which
# keeps carrying SSH. Both sides then measure each other at once over that
# link -- the dongle reports the peer's RSSI on the AP as well as on the
# station -- and each Pi judges only its own measurement. The link is always
# taken down on exit (and by wifi_link.sh's own timer otherwise).
#
# Usage:
#   ./test_wifi_multihost.sh [wifi_test options]
#   e.g. ./test_wifi_multihost.sh --rounds 50 --rssi-at-1m -35 --max-distance-m 1
# The same options go to both sides, so both judge with the same model.
#
# Assumes passwordless SSH and sudo on both hosts, ~/project/iotauth on
# both with this directory present, and the dongle as wlan1 on both.
# ==============================================================================

set -eo pipefail

STATION_HOST="pi42@pi42"
AP_HOST="pi43@pi43"
WIFI_DIR="project/iotauth/entity/c/wifi_com"
AP_LOG="/tmp/wifi_test_ap.log"
LINK_MINUTES=10
TEST_ARGS="$*"

ssh_to() {
    ssh -o BatchMode=yes -o ConnectTimeout=15 "$1" "$2" < /dev/null
}

cleanup() {
    for h in "$STATION_HOST" "$AP_HOST"; do
        ssh_to "$h" "pkill -f '[.]/wifi_test' 2>/dev/null; $WIFI_DIR/wifi_link.sh down" > /dev/null 2>&1 || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "[1/3] Preparing both Pis (hostapd, wifi_test build)..."
for h in "$STATION_HOST" "$AP_HOST"; do
    # The hostapd package ships its service masked here; it is only ever
    # started by wifi_link.sh, on the dongle.
    ssh_to "$h" "dpkg -s hostapd > /dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q hostapd > /dev/null; cd $WIFI_DIR && chmod +x wifi_link.sh && gcc -O2 -Wall -Wextra -o wifi_test wifi_test.c wifi_rssi.c -lm"
done
cleanup

echo "[2/3] Bringing up the dongle link (AP ${AP_HOST#*@}, station ${STATION_HOST#*@})..."
ssh_to "$AP_HOST" "$WIFI_DIR/wifi_link.sh ap $LINK_MINUTES"
ssh_to "$STATION_HOST" "$WIFI_DIR/wifi_link.sh sta $LINK_MINUTES"

echo "[3/3] Measuring both ways..."
ssh_to "$AP_HOST" "cd $WIFI_DIR && rm -f $AP_LOG && (setsid nohup timeout 120 ./wifi_test --role ap $TEST_ARGS > $AP_LOG 2>&1 < /dev/null &)"
sleep 1
STATUS=0
ssh_to "$STATION_HOST" "cd $WIFI_DIR && timeout 120 ./wifi_test --role station --peer 192.168.77.1 $TEST_ARGS" 2>&1 | LC_ALL=C sed -u "s/^/[${STATION_HOST#*@} station] /" || STATUS=$?
sleep 1
ssh_to "$AP_HOST" "cat $AP_LOG" | LC_ALL=C sed "s/^/[${AP_HOST#*@} ap] /"
# Each side's own verdict decides; wifi_test exits 0 only on its own PASS.
if ! ssh_to "$AP_HOST" "grep -q 'WIFI RANGE: local .*result=PASS' $AP_LOG"; then
    STATUS=1
fi
exit "$STATUS"
