#!/usr/bin/env bash

# Usage: ./config_and_clients.sh <number-of-instances> <csv-file>

# 1. Generates the client configs via config_generator.js
# 2. Launches server and clients via run_clients.sh

if [ $# -ne 2 ]; then
  echo "Usage: $0 <number_of_instances> <csv_file>"
  exit 1
fi

COUNT=$1
CSV="$2"

# Generate config files
echo "→ Generating $COUNT client config files..."
node config_generator.js "$COUNT"
if [ $? -ne 0 ]; then
  echo "config_generator.js failed"
  exit 1
fi

# Launch server and clients
echo "→ Launching $COUNT servers and clients with CSV: $CSV"
./run_clients.sh "$COUNT" "$CSV"
if [ $? -ne 0 ]; then
  echo "run_clients.sh failed"
  exit 1
fi

echo "Finished."
