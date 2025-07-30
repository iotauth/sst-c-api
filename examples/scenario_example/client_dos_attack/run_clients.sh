#!/usr/bin/env bash

# runClients.sh
# Usage: ./runClients.sh <number-of-clients>

launch_terminal() {
  local cmd="$1"
  if [[ "$OS" == "Darwin" ]]; then
    osascript -e "tell application \"Terminal\" to do script \"$cmd\""
  elif command -v gnome-terminal &> /dev/null; then
    gnome-terminal -- bash -c "$cmd; exec bash" &
  elif command -v xterm &> /dev/null; then
    xterm -hold -e "$cmd" &
  else
    echo "No GUI terminal found; running headless: $cmd"
    eval "$cmd &"
  fi
}

if [ $# -ne 2 ]; then
  echo "Usage: $0 <number-of-instances> <csv-file>"
  exit 1
fi

COUNT=$1
CSV="$2"
SERVER_BIN="../build/server"
CLIENT_BIN="../build/client"

for bin in "$SERVER_BIN" "$CLIENT_BIN"; do
  if [ ! -x "$bin" ]; then
    echo "Executable not found or not runnable at $bin"
    exit 1
  fi
done

OS=$(uname)

CFG="../../server_client_example/c_server.config"
SHCMD="cd '$(pwd)' && $SERVER_BIN '$CFG'"
launch_terminal "$SHCMD"

for (( i=0; i<COUNT; i++ )); do
  CFG="../config/client${i}.config"
  SHCMD="cd '$(pwd)' && $CLIENT_BIN '$CFG' '$CSV'"
  launch_terminal "$SHCMD"
done


echo "Launched $COUNT clients using $SERVER_BIN and $CLIENT_BIN."
