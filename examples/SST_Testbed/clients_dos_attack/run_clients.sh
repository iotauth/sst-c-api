#!/usr/bin/env bash

# run_clients.sh
# Usage: ./run_clients.sh <number-of-clients> <csv-file> [-metrics] [source-ip]

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

# Require 2 to 4 arguments
if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "Usage: $0 <number-of-clients> <csv-file> [-metrics] [source-ip]"
  exit 1
fi

COUNT="$1"
CSV="$2"
METRICS_FLAG=""
SRC_IP=""

for arg in "${@:3}"; do
  if [[ "$arg" == "-metrics" ]]; then
    if [[ -n "$METRICS_FLAG" ]]; then
      echo "Duplicate -metrics flag."
      echo "Usage: $0 <number-of-clients> <csv-file> [-metrics] [source-ip]"
      exit 1
    fi
    METRICS_FLAG="-metrics"
  elif [[ -z "$SRC_IP" ]]; then
    SRC_IP="$arg"
  else
    echo "Too many positional arguments."
    echo "Usage: $0 <number-of-clients> <csv-file> [-metrics] [source-ip]"
    exit 1
  fi
done

SERVER_BIN="../build/server"
CLIENT_BIN="../build/client"

for bin in "$SERVER_BIN" "$CLIENT_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "Executable not found or not runnable at $bin"
    exit 1
  fi
done

# Select protocol profile by CSV filename.
# If filename contains "udp" (case-insensitive), use UDP configs.
CSV_BASENAME="$(basename "$CSV")"
CSV_BASENAME_LC="$(echo "$CSV_BASENAME" | tr '[:upper:]' '[:lower:]')"
SERVER_CFG="../config/server.config"
CLIENT_CFG_SUFFIX=""
PROTOCOL_PROFILE="TCP"
if [[ "$CSV_BASENAME_LC" == *"udp"* ]]; then
  SERVER_CFG="../config/server_udp.config"
  CLIENT_CFG_SUFFIX="_udp"
  PROTOCOL_PROFILE="UDP"
fi

UDP_WORKERS=""
if [[ "$PROTOCOL_PROFILE" == "UDP" ]]; then
  UDP_WORKERS=$((COUNT + 3))
  if (( UDP_WORKERS > 512 )); then
    UDP_WORKERS=512
  fi
  if (( UDP_WORKERS < 1 )); then
    UDP_WORKERS=1
  fi
fi

# In UDP profile, stagger client launches to reduce handshake stampede.
# Although this goes against the attack model, launching all clients at once overwhelms the server and causes a race between the clients.
LAUNCH_STAGGER_SEC=0
if [[ "$PROTOCOL_PROFILE" == "UDP" ]]; then
  LAUNCH_STAGGER_SEC=0.2
fi

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
if [[ "$PROTOCOL_PROFILE" == "UDP" ]]; then
  SHCMD="cd '$(pwd)' && SST_UDP_WORKERS='$UDP_WORKERS' $SERVER_BIN '$SERVER_CFG'"
else
  SHCMD="cd '$(pwd)' && $SERVER_BIN '$SERVER_CFG'"
fi
launch_terminal "$SHCMD" "no"

# Give the server process time to start before clients begin connecting.
# UDP server creates a worker pool and binds sockets at startup, so it needs more time before clients can connect.
SERVER_STARTUP_DELAY_SEC=2
sleep "$SERVER_STARTUP_DELAY_SEC"

# Launch clients
for (( i=0; i<COUNT; i++ )); do
  CFG="../config_clones/client${i}${CLIENT_CFG_SUFFIX}.config"

  if [[ ! -f "$CFG" ]]; then
    echo "Missing client config: $CFG"
    echo "Run ./clients_dos_setup.sh $COUNT to regenerate cloned configs."
    exit 1
  fi

  SHCMD="cd '$(pwd)' && SST_MALICIOUS_CLIENTS='$COUNT' $CLIENT_BIN '$CFG' '$CSV'"
  if [[ -n "$METRICS_FLAG" ]]; then
    SHCMD+=" '$METRICS_FLAG'"
  fi
  if [[ -n "$SRC_IP" ]]; then
    SHCMD+=" '$SRC_IP'"
  fi

  launch_terminal "$SHCMD" "$USE_SUDO"
  if [[ "$LAUNCH_STAGGER_SEC" != "0" ]]; then
    sleep "$LAUNCH_STAGGER_SEC"
  fi
done

echo "Launched $COUNT clients using $PROTOCOL_PROFILE profile ($SERVER_CFG, client*${CLIENT_CFG_SUFFIX}.config)."
