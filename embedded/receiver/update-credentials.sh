#!/bin/bash
#
# This script copies the necessary security credentials from the iotauth
# project's output directory into the receiver's local, stable staging area.
#
# This decouples the receiver application from the specific directory
# structure of the iotauth project.
#
# USAGE: Run this script from the 'receiver' directory after ensuring
#        the iotauth server has generated the latest credentials.
#        $ ./update-credentials.sh

# --- Configuration ---
# The relative path to the root of the iotauth project directory.
# Adjust this if your directory structure is different.
AUTH_PROJECT_ROOT="../../../iotauth"

# The stable staging directory for the receiver's credentials.
# This path should match what's in lifi_receiver.config
RECEIVER_STAGING_DIR="./config/credentials"

# --- Script ---
set -e # Exit immediately if a command exits with a non-zero status.

echo "Looking for iotauth project at: ${AUTH_PROJECT_ROOT}"

if [ ! -d "${AUTH_PROJECT_ROOT}" ]; then
    echo "Error: iotauth project directory not found."
    echo "Please check the AUTH_PROJECT_ROOT variable in this script."
    exit 1
fi

echo "Copying latest credentials to ${RECEIVER_STAGING_DIR}..."

# Define source paths
AUTH_CERT_PATH="${AUTH_PROJECT_ROOT}/entity/auth_certs/Auth101EntityCert.pem"
CLIENT_KEY_PATH="${AUTH_PROJECT_ROOT}/entity/credentials/keys/net1/Net1.ClientKey.pem"

# Check if source files exist before copying
if [ ! -f "${AUTH_CERT_PATH}" ]; then
    echo "Error: Auth certificate not found at ${AUTH_CERT_PATH}"
    exit 1
fi
if [ ! -f "${CLIENT_KEY_PATH}" ]; then
    echo "Error: Client key not found at ${CLIENT_KEY_PATH}"
    exit 1
fi

# Copy the files
cp "${AUTH_CERT_PATH}" "${RECEIVER_STAGING_DIR}/"
cp "${CLIENT_KEY_PATH}" "${RECEIVER_STAGING_DIR}/"

echo "Credentials updated successfully."
