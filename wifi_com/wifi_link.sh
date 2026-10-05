#!/bin/bash

# ==============================================================================
# Brings a direct Wi-Fi link between two Raspberry Pis up or down on a USB
# Wi-Fi dongle (TP-Link Archer T2U Nano, rtw88_8821au), leaving the on-board
# wlan0 -- which carries SSH/Tailscale -- alone:
#
#   ./wifi_link.sh ap  [MINUTES]   # this Pi opens AP "iotauth-wifi" on the
#                                  # dongle, 192.168.77.1
#   ./wifi_link.sh sta [MINUTES]   # this Pi joins it on its dongle,
#                                  # 192.168.77.2
#   ./wifi_link.sh down            # takes the link down and hands the dongle
#                                  # back to NetworkManager
#
# The dongle is its own radio, so the channel is fixed (WIFI_CHANNEL, default
# 36) instead of following wlan0's campus AP. The link gets no gateway, so no
# other traffic is routed over it. Every "up" first arms a systemd timer that
# runs "down" after MINUTES (default 15), so a link that misbehaves is
# removed even if this Pi becomes unreachable.
#
# The AP uses the system's regulatory domain as is: setting country_code in
# hostapd.conf when the domain already matches makes hostapd wait forever in
# COUNTRY_UPDATE for a change event that never comes (beacons go out, but no
# station can authenticate).
#
# Requires sudo; "ap" requires hostapd (apt-get install hostapd).
# Environment: WIFI_IFACE (default wlan1), WIFI_CHANNEL (default 36).
# ==============================================================================

set -e

ROLE="$1"
MINUTES="${2:-15}"
IFACE="${WIFI_IFACE:-wlan1}"
CHANNEL="${WIFI_CHANNEL:-36}"
SSID="iotauth-wifi"
PASSPHRASE="iotauth-test-link"
AP_ADDR="192.168.77.1/24"
STA_ADDR="192.168.77.2/24"
RUN_DIR="/run/wifi_test"
REVERT_UNIT="iotauth-wifi-test-revert"
SCRIPT="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
IW=/usr/sbin/iw

down() {
    for pid in "$RUN_DIR"/*.pid; do
        [ -f "$pid" ] && sudo kill "$(cat "$pid")" 2>/dev/null || true
    done
    sudo rm -rf "$RUN_DIR"
    if $IW dev "$IFACE" info > /dev/null 2>&1; then
        sudo ip addr flush dev "$IFACE"
        sudo nmcli dev set "$IFACE" managed yes 2>/dev/null || true
    fi
    sudo systemctl stop "$REVERT_UNIT.timer" 2>/dev/null || true
    echo "Wi-Fi link removed."
}

# Takes the dongle from NetworkManager and arms the revert.
prepare() {
    if [ "$IFACE" = wlan0 ]; then
        echo "Refusing to use wlan0: it carries this Pi's own connection."
        exit 1
    fi
    if ! $IW dev "$IFACE" info > /dev/null 2>&1; then
        echo "No $IFACE: is the Wi-Fi dongle plugged in?"
        exit 1
    fi
    sudo systemctl stop "$REVERT_UNIT.timer" 2>/dev/null || true
    sudo systemctl reset-failed "$REVERT_UNIT.service" "$REVERT_UNIT.timer" 2>/dev/null || true
    sudo systemd-run --quiet --unit="$REVERT_UNIT" --on-active="${MINUTES}m" \
        --setenv=WIFI_IFACE="$IFACE" /bin/bash "$SCRIPT" down
    echo "Armed: the link is removed in $MINUTES min ($REVERT_UNIT.timer)."
    sudo nmcli dev set "$IFACE" managed no
    sudo ip addr flush dev "$IFACE"
    sudo ip link set "$IFACE" up
    sudo mkdir -p "$RUN_DIR"
}

case "$ROLE" in
down)
    down
    ;;
ap)
    prepare
    if [ "$CHANNEL" -le 14 ]; then HW_MODE=g; else HW_MODE=a; fi
    sudo tee "$RUN_DIR/hostapd.conf" > /dev/null <<EOF
interface=$IFACE
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
    echo "Starting AP $SSID on $IFACE, channel $CHANNEL..."
    sudo hostapd -B -P "$RUN_DIR/hostapd.pid" -f "$RUN_DIR/hostapd.log" \
        "$RUN_DIR/hostapd.conf" || { sudo cat "$RUN_DIR/hostapd.log"; exit 1; }
    sudo ip addr add "$AP_ADDR" dev "$IFACE"
    echo "AP up: $IFACE ${AP_ADDR%/*}"
    ;;
sta)
    prepare
    sudo tee "$RUN_DIR/wpa.conf" > /dev/null <<EOF
ctrl_interface=$RUN_DIR/wpa_ctrl
p2p_disabled=1
network={
    ssid="$SSID"
    psk="$PASSPHRASE"
    key_mgmt=WPA-PSK
}
EOF
    sudo wpa_supplicant -B -i "$IFACE" -c "$RUN_DIR/wpa.conf" \
        -P "$RUN_DIR/wpa_supplicant.pid" -f "$RUN_DIR/wpa_supplicant.log"
    for _ in $(seq 1 20); do
        $IW dev "$IFACE" link | grep -q "^Connected" && break
        sleep 1
    done
    if ! $IW dev "$IFACE" link | grep -q "^Connected"; then
        echo "$IFACE did not associate with $SSID:"
        sudo tail -20 "$RUN_DIR/wpa_supplicant.log"
        exit 1
    fi
    sudo ip addr add "$STA_ADDR" dev "$IFACE"
    echo "Station up: $IFACE ${STA_ADDR%/*}"
    $IW dev "$IFACE" link | grep -E "Connected|freq|signal"
    ;;
*)
    echo "Usage: $0 ap [MINUTES] | sta [MINUTES] | down"
    exit 1
    ;;
esac
