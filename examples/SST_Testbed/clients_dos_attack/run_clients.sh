#!/usr/bin/env bash

# run_clients.sh
# Usage: ./run_clients.sh <number-of-clients> <csv-file> [source-ip]

OS=$(uname)
SUDO_KEEPALIVE_PID=""

start_sudo_session() {
  # Ask once for sudo credentials.
  if ! sudo -v; then
    echo "Failed to authenticate with sudo."
    exit 1
  fi

  # Keep sudo ticket alive while this script runs.
  (
    while true; do
      sudo -n true
      sleep 50
    done
  ) &
  SUDO_KEEPALIVE_PID=$!
}

stop_sudo_session() {
  if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  fi
}

launch_terminal() {
  local cmd="$1"
  local use_sudo="$2" # "yes" or "no"

  if [[ "$OS" == "Darwin" && "$use_sudo" == "yes" ]]; then
    sudo -n bash -lc "$cmd" &
    return
  fi

  if [[ "$OS" == "Darwin" ]]; then
    osascript -e "tell application \"Terminal\" to do script \"$cmd\""
  elif command -v gnome-terminal &> /dev/null; then
    if [[ "$use_sudo" == "yes" ]]; then
      gnome-terminal -- bash -c "sudo -n bash -lc \"$cmd\"; exec bash" &
    else
      gnome-terminal -- bash -c "$cmd; exec bash" &
    fi
  elif command -v xterm &> /dev/null; then
    if [[ "$use_sudo" == "yes" ]]; then
      xterm -hold -e "sudo -n bash -lc \"$cmd\"" &
    else
      xterm -hold -e "$cmd" &
    fi
  else
    echo "No GUI terminal found; running headless: $cmd"
    if [[ "$use_sudo" == "yes" ]]; then
      sudo -n bash -lc "$cmd" &
    else
      eval "$cmd &"
    fi
  fi
}

# Require 2 or 3 arguments
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <number-of-clients> <csv-file> [source-ip]"
  exit 1
fi

COUNT="$1"
CSV="$2"
SRC_IP="${3:-}" # empty if not provided

SERVER_BIN="../build/server"
CLIENT_BIN="../build/client"

for bin in "$SERVER_BIN" "$CLIENT_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "Executable not found or not runnable at $bin"
    exit 1
  fi
done

# Decide whether to use sudo.
# Raw socket attacks (DOSS/DOSU) require elevated privileges.
USE_SUDO="no"
if [[ -n "$SRC_IP" ]]; then
  USE_SUDO="yes"
elif [[ -f "$CSV" ]] && grep -Eiq ',[[:space:]]*DOS(S|U)[[:space:]]*(,|$)' "$CSV"; then
  USE_SUDO="yes"
fi

if [[ "$USE_SUDO" == "yes" ]]; then
  start_sudo_session
  trap stop_sudo_session EXIT
fi

# Launch server
CFG="../../server_client_example/c_server.config"
SHCMD="cd '$(pwd)' && $SERVER_BIN '$CFG'"
launch_terminal "$SHCMD" "no"

# Launch clients
for (( i=0; i<COUNT; i++ )); do
  CFG="../config/client${i}.config"

  if [[ -n "$SRC_IP" ]]; then
    # With source IP: third argument
    SHCMD="cd '$(pwd)' && $CLIENT_BIN '$CFG' '$CSV' '$SRC_IP'"
  else
    # No source IP: only config + CSV
    SHCMD="cd '$(pwd)' && $CLIENT_BIN '$CFG' '$CSV'"
  fi

  launch_terminal "$SHCMD" "$USE_SUDO"
done

echo "Launched $COUNT clients using $SERVER_BIN and $CLIENT_BIN."
