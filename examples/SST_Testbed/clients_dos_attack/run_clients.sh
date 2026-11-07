#!/usr/bin/env bash

# run_clients.sh
# Usage: ./run_clients.sh <number-of-clients> <csv-file> [-metrics] [source-ip] [--protocol TCP|UDP] [--dry-run]

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

usage() {
  echo "Usage: $0 <number-of-clients> <csv-file> [-metrics] [source-ip] [--protocol TCP|UDP] [--dry-run]" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

COUNT="$1"
CSV="$2"
shift 2
METRICS_FLAG=""
SRC_IP=""
PROTOCOL_PROFILE=""
DRY_RUN="no"
if [[ ! "$COUNT" =~ ^[1-9][0-9]*$ || ! -f "$CSV" || ! -r "$CSV" ]]; then
  echo "Provide a positive client count and a readable scenario CSV." >&2
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -metrics)
      if [[ -n "$METRICS_FLAG" ]]; then
        echo "Duplicate -metrics flag." >&2
        exit 1
      fi
      METRICS_FLAG="-metrics"
      ;;
    --protocol)
      if [[ $# -lt 2 || -n "$PROTOCOL_PROFILE" ]]; then
        usage
        exit 1
      fi
      PROTOCOL_PROFILE="$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"
      if [[ "$PROTOCOL_PROFILE" != TCP && "$PROTOCOL_PROFILE" != UDP ]]; then
        echo "Protocol must be TCP or UDP." >&2
        exit 1
      fi
      shift
      ;;
    --dry-run) DRY_RUN="yes" ;;
    -*) usage; exit 1 ;;
    *)
      if [[ -n "$SRC_IP" ]]; then
        usage
        exit 1
      fi
      SRC_IP="$1"
      ;;
  esac
  shift
done

# Only the scenario type column determines the required transport.
if ! SCENARIO_PROTOCOL=$(awk -F, '
  {
    type = toupper($3)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", type)
    if (type == "DOSU") udp = 1
    if (type == "DOSS") tcp = 1
  }
  END {
    if (tcp && udp) exit 1
    print udp ? "UDP" : tcp ? "TCP" : "ANY"
  }' "$CSV"); then
  echo "A scenario cannot mix DOSS (TCP) and DOSU (UDP)." >&2
  exit 1
fi
if [[ -n "$PROTOCOL_PROFILE" && "$SCENARIO_PROTOCOL" != ANY &&
      "$PROTOCOL_PROFILE" != "$SCENARIO_PROTOCOL" ]]; then
  echo "The requested protocol conflicts with the scenario: $SCENARIO_PROTOCOL required." >&2
  exit 1
fi
if [[ -z "$PROTOCOL_PROFILE" ]]; then
  PROTOCOL_PROFILE="$SCENARIO_PROTOCOL"
  if [[ "$PROTOCOL_PROFILE" == ANY ]]; then PROTOCOL_PROFILE="TCP"; fi
fi

CLIENT_BIN="../build/client"

for bin in "$CLIENT_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "Executable not found or not runnable at $bin"
    exit 1
  fi
done

CLIENT_CFG_SUFFIX=""
if [[ "$PROTOCOL_PROFILE" == UDP ]]; then CLIENT_CFG_SUFFIX="_udp"; fi

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
elif [[ "$SCENARIO_PROTOCOL" != ANY ]]; then
  USE_SUDO="yes"
fi

if [[ "$USE_SUDO" == "yes" && "$DRY_RUN" == "no" ]]; then
  start_sudo_session
  trap stop_sudo_session EXIT
fi

# Launch clients
for (( i=0; i<COUNT; i++ )); do
  CFG="../config_clones/client${i}${CLIENT_CFG_SUFFIX}.config"

  if [[ ! -f "$CFG" ]]; then
    echo "Missing client config: $CFG"
    echo "Run ./clients_dos_setup.sh $COUNT to regenerate cloned configs."
    exit 1
  fi

  SHCMD="cd '$(pwd)' && $CLIENT_BIN '$CFG' '$CSV'"
  if [[ -n "$METRICS_FLAG" ]]; then
    SHCMD+=" '$METRICS_FLAG'"
  fi
  if [[ -n "$SRC_IP" ]]; then
    SHCMD+=" '$SRC_IP'"
  fi

  if [[ "$DRY_RUN" == "yes" ]]; then
    printf 'Would launch (%s): %s\n' "$PROTOCOL_PROFILE" "$SHCMD"
    continue
  fi
  launch_terminal "$SHCMD" "$USE_SUDO"
  if [[ "$LAUNCH_STAGGER_SEC" != "0" ]]; then
    sleep "$LAUNCH_STAGGER_SEC"
  fi
done

if [[ "$DRY_RUN" == "yes" ]]; then
  echo "Validated $COUNT clients using $PROTOCOL_PROFILE profile."
else
  echo "Launched $COUNT clients using $PROTOCOL_PROFILE profile (client*${CLIENT_CFG_SUFFIX}.config)."
fi
