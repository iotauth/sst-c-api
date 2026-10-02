#!/bin/bash

# ==============================================================================
# Brings a direct Wi-Fi test link between two Raspberry Pis up or down, next
# to (never instead of) their existing wlan0 connection, which keeps carrying
# SSH/Tailscale:
#
#   ./wifi_link.sh ap  [MINUTES]   # this Pi opens AP "iotauth-test" on uap0,
#                                  # 192.168.77.1, on wlan0's current channel
#   ./wifi_link.sh sta [MINUTES]   # this Pi joins it on wlan1, 192.168.77.2
#   ./wifi_link.sh down            # removes uap0/wlan1 and only the
#                                  # hostapd/wpa_supplicant started here
#
# The on-chip CYW43455 allows one AP next to one station only on the same
# channel, so the AP follows whatever channel wlan0 is on right now. Neither
# test interface gets a gateway, so no other traffic is routed over it, and
# both are kept out of NetworkManager. Every "up" first arms a systemd timer
# that runs "down" after MINUTES (default 15), so a link that misbehaves is
# removed even if this Pi becomes unreachable.
#
# The AP uses the system's regulatory domain as is: setting country_code in
# hostapd.conf when the domain already matches makes hostapd wait forever in
# COUNTRY_UPDATE for a change event that never comes (beacons go out, but no
# station can authenticate).
#
# Requires sudo; "ap" requires hostapd (apt-get install hostapd).
# ==============================================================================

set -e

ROLE="$1"
MINUTES="${2:-15}"
SSID="iotauth-test"
PASSPHRASE="iotauth-test-link"
RUN_DIR="/run/wifi_test"
NM_CONF="/etc/NetworkManager/conf.d/99-iotauth-wifi-test.conf"
REVERT_UNIT="iotauth-wifi-test-revert"
SCRIPT="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
IW=/usr/sbin/iw

down() {
    for pid in "$RUN_DIR"/*.pid; do
        [ -f "$pid" ] && sudo kill "$(cat "$pid")" 2>/dev/null || true
    done
    sudo rm -rf "$RUN_DIR"
    for dev in uap0 wlan1; do
        if $IW dev "$dev" info > /dev/null 2>&1; then sudo $IW dev "$dev" del; fi
    done
    if [ -f "$NM_CONF" ]; then
        sudo rm -f "$NM_CONF"
        sudo nmcli general reload conf
    fi
    sudo systemctl stop "$REVERT_UNIT.timer" 2>/dev/null || true
    echo "Wi-Fi test link removed."
}

# wlan0's MAC with the locally administered bit set, so the second interface
# never shares wlan0's address.
local_mac() {
    local mac first
    mac=$(cat /sys/class/net/wlan0/address)
    first=$(( 0x${mac%%:*} | 0x02 ))
    printf '%02x:%s' "$first" "${mac#*:}"
}

# Creates DEV next to wlan0, outside NetworkManager, and arms the revert.
add_interface() {
    local dev="$1" type="$2"
    sudo systemctl stop "$REVERT_UNIT.timer" 2>/dev/null || true
    sudo systemctl reset-failed "$REVERT_UNIT.service" "$REVERT_UNIT.timer" 2>/dev/null || true
    sudo systemd-run --quiet --unit="$REVERT_UNIT" --on-active="${MINUTES}m" \
        /bin/bash "$SCRIPT" down
    echo "Armed: the test link is removed in $MINUTES min ($REVERT_UNIT.timer)."
    printf '[keyfile]\nunmanaged-devices=interface-name:uap0;interface-name:wlan1\n' |
        sudo tee "$NM_CONF" > /dev/null
    sudo nmcli general reload conf
    sudo mkdir -p "$RUN_DIR"
    sudo $IW dev wlan0 interface add "$dev" type "$type" addr "$(local_mac)"
}

case "$ROLE" in
down)
    down
    ;;
ap)
    # wlan0's channel, which the AP must share.
    FREQ=$($IW dev wlan0 info | awk '/channel/ {gsub(/\(/, "", $3); print $3}')
    CHANNEL=$($IW dev wlan0 info | awk '/channel/ {print $2}')
    [ -n "$CHANNEL" ] || { echo "wlan0 is not connected; no channel to share."; exit 1; }
    if [ "$FREQ" -lt 3000 ]; then HW_MODE=g; else HW_MODE=a; fi
    add_interface uap0 __ap
    sudo tee "$RUN_DIR/hostapd.conf" > /dev/null <<EOF
interface=uap0
driver=nl80211
ssid=$SSID
hw_mode=$HW_MODE
channel=$CHANNEL
ieee80211n=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$PASSPHRASE
EOF
    echo "Starting AP $SSID on channel $CHANNEL ($FREQ MHz)..."
    sudo hostapd -B -P "$RUN_DIR/hostapd.pid" -f "$RUN_DIR/hostapd.log" \
        "$RUN_DIR/hostapd.conf" || { sudo cat "$RUN_DIR/hostapd.log"; exit 1; }
    sudo ip addr add 192.168.77.1/24 dev uap0
    sudo ip link set uap0 up
    echo "AP up: uap0 192.168.77.1"
    ;;
sta)
    add_interface wlan1 managed
    sudo tee "$RUN_DIR/wpa.conf" > /dev/null <<EOF
ctrl_interface=$RUN_DIR/wpa_ctrl
p2p_disabled=1
network={
    ssid="$SSID"
    psk="$PASSPHRASE"
    key_mgmt=WPA-PSK
}
EOF
    sudo ip link set wlan1 up
    sudo wpa_supplicant -B -i wlan1 -c "$RUN_DIR/wpa.conf" \
        -P "$RUN_DIR/wpa_supplicant.pid" -f "$RUN_DIR/wpa_supplicant.log"
    for _ in $(seq 1 20); do
        $IW dev wlan1 link | grep -q "^Connected" && break
        sleep 1
    done
    if ! $IW dev wlan1 link | grep -q "^Connected"; then
        echo "wlan1 did not associate with $SSID:"
        sudo tail -20 "$RUN_DIR/wpa_supplicant.log"
        exit 1
    fi
    sudo ip addr add 192.168.77.2/24 dev wlan1
    echo "Station up: wlan1 192.168.77.2"
    $IW dev wlan1 link | grep -E "Connected|freq|signal"
    ;;
*)
    echo "Usage: $0 ap [MINUTES] | sta [MINUTES] | down"
    exit 1
    ;;
esac
