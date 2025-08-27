#!/usr/bin/env bash
set -euo pipefail

# Usage: ./clients_dos_setup.sh <number-of-clients>

# Function to launch a terminal with a command
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

# Parameters check
if [ $# -lt 1 ]; then
  echo "Usage: $0 <number-of-clients> [-p|--password <password>]"
  exit 1
fi

COUNT="$1"
shift

PASSWORD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--password)
      if [[ $# -lt 2 ]]; then
        echo "Error: $1 requires a value"
        exit 1
      fi
      PASSWORD="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "Number of clients: $COUNT"
if [[ -n "$PASSWORD" ]]; then
  echo "Password: $PASSWORD"
else
  echo "Password not provided"
fi

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Directory and commands for regenerating Auth with the new graph generated
EXAMPLES_DIR="../../../../../examples"
CLEANALL='./cleanAll.sh'
if [[ -n "$PASSWORD" ]]; then
  GENERATEALL="./generateAll.sh -g configs/custom_clients.graph -p $PASSWORD"
else
  GENERATEALL="./generateAll.sh -g configs/custom_clients.graph"
fi

# Auth Server directory and command for starting it
SERVER_DIR="../../../../../auth/auth-server"
if [[ -n "$PASSWORD" ]]; then
  SERVER_CMD="java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties --password $PASSWORD"
else
  SERVER_CMD="java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties"
fi

# 1) Run the graph file generator
echo
echo "Generating the graph file"
cd "$SCRIPT_DIR"
command -v node >/dev/null || { echo "Node.js not found"; exit 1; }
[ -f graph_generator.js ] || { echo "graph_generator.js not found"; exit 1; }
node graph_generator.js "$COUNT"

# 2) Use the graph
echo
echo "Generate Auth with the new graph"
cd "$EXAMPLES_DIR"
$CLEANALL
$GENERATEALL

# 3) Launch the Auth server after doing generateAll.sh
echo
echo "Launching Auth server"

# If the server is already running, stop it first
if pgrep -f -q "$SERVER_CMD"; then
  echo "Stopping existing auth server"
  pkill -f "$SERVER_CMD" || true
  for ((t=0; t<10; t++)); do # t is the timeout in seconds
    pgrep -f -q "$SERVER_CMD" || { echo "Stopped."; break; }
    sleep 1
  done
  pgrep -f -q "$SERVER_CMD" && { echo "Force kill..."; pkill -9 -f "$SERVER_CMD" || true; }
# If the server is not running, then continue
else
  echo "No running auth server found."
fi

OS=$(uname)
SHCMD="cd '$SCRIPT_DIR' && cd '$SERVER_DIR' && $SERVER_CMD"

# Launch in a new terminal with the server command
launch_terminal "$SHCMD"

# 4) Return to the original directory and generate client configs
echo
echo "Generating client configs"
cd "$SCRIPT_DIR"

# ensure the directory is correct
[ -f config_generator.js ] || { echo "config_generator.js not found in $SCRIPT_DIR"; exit 1; }

# run the generator with the count argument
node config_generator.js "$COUNT"

echo
echo "The setup for doing DoS attacks using multiple clients is complete."
