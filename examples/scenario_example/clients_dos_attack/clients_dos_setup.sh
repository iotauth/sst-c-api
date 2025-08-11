#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run_graph_and_setup.sh <count> <password>

# Parameters check
if [ $# -ne 3 ]; then
  echo "Usage: $0 <count> <password>"
  exit 1
fi

COUNT="$1"
PASSWORD="$2"

# Directory and commands for regenerating Auth with the new graph generated
EXAMPLES_DIR="../../../../../examples"
CLEANALL='./cleanAll.sh'
GENERATEALL='./generateAll.sh -g configs/custom_clients.graph'

# Auth Server directory and command for starting it
SERVER_DIR="../auth/auth-server"
SERVER_CMD='java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties'

# 1) Run the generator
echo
echo "Generating the graph file"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
command -v node >/dev/null || { echo "Node.js not found"; exit 1; }
[ -f graph_generator.js ] || { echo "graph_generator.js not found"; exit 1; }
node graphGenerator.js "$COUNT"

# 2) Use the graph
echo
echo "Generate Auth with the new graph"
cd "$EXAMPLES_DIR"
./cleanAll.sh

echo "→ Running modified generateAll.sh"
if printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | eval "$GENERATEALL"; then
  echo "generateAll.sh finished"
else
  echo "✗ generateAll.sh failed"
  exit 1
fi

# 3) Launch the Auth server after doing generateAll.sh
echo
echo "Launching Auth server"
cd "$SERVER_DIR"

# If the server is already running, stop it first
if pgrep -f -x -q "$SERVER_CMD"; then
  echo "Stopping existing auth server"
  pkill -f -x "$SERVER_CMD" || true
  for ((t=0; t<10; t++)); do # t is the timeout in seconds
    pgrep -f -x -q "$SERVER_CMD" || { echo "Stopped."; break; }
    sleep 1
  done
  pgrep -f -x -q "$SERVER_CMD" && { echo "Force kill..."; pkill -9 -f -x "$SERVER_CMD" || true; }
# If the server is not running, just continue
else
  echo "No running auth server found."
fi

echo "Starting auth server"
printf '%s\n' "$PASSWORD" | bash -lc "$SERVER_CMD &"

# 4) Return to the original directory and generate client configs
echo
echo "Generating client configs"
cd "$SCRIPT_DIR"

# ensure the directory is correct
[ -f configGenerator.js ] || { echo "configGenerator.js not found in $SCRIPT_DIR"; exit 1; }

# run the generator with the count argument
node configGenerator.js "$COUNT"

echo
echo "The setup for doing DoS attacks using multiple clients is complete."
