#!/usr/bin/env bash

# run_clients.sh
# Usage: ./run_clients.sh <number-of-clients> <csv-file> [source-ip]

OS=$(uname)

launch_terminal() {
  local cmd="$1"
  local use_sudo="$2" # "yes" or "no"

  if [[ "$OS" == "Darwin" ]]; then
    if [[ "$use_sudo" == "yes" ]]; then
      sudo osascript -e "tell application \"Terminal\" to do script \"$cmd\""
    else
      osascript -e "tell application \"Terminal\" to do script \"$cmd\""
    fi
  elif command -v gnome-terminal &> /dev/null; then
    if [[ "$use_sudo" == "yes" ]]; then
      sudo gnome-terminal -- bash -c "$cmd; exec bash" &
    else
      gnome-terminal -- bash -c "$cmd; exec bash" &
    fi
  elif command -v xterm &> /dev/null; then
    if [[ "$use_sudo" == "yes" ]]; then
      sudo xterm -hold -e "$cmd" &
    else
      xterm -hold -e "$cmd" &
    fi
  else
    echo "No GUI terminal found; running headless: $cmd"
    if [[ "$use_sudo" == "yes" ]]; then
      eval "sudo $cmd &"
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

# Decide whether to use sudo based on whether src IP is provided
USE_SUDO="no"
if [[ -n "$SRC_IP" ]]; then
  USE_SUDO="yes"
fi

# Launch server
CFG="../../server_client_example/c_server.config"
SHCMD="cd '$(pwd)' && $SERVER_BIN '$CFG'"
launch_terminal "$SHCMD" "$no"

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
