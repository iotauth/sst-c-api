# Secure Li-Fi Communication with SST

This project aims to establish secure, real-time Li-Fi communication between edge devices using AES-GCM encryption with session keys provisioned by an SST-based authentication server.

## Project Overview

This repository contains the embedded software for a secure Li-Fi communication system. It consists of two main components:

*   **Sender**: A Raspberry Pi Pico responsible for encrypting and transmitting data via a Li-Fi module.
*   **Receiver**: A Raspberry Pi 4 that receives the Li-Fi signal, decrypts the data, and is responsible for provisioning session keys from an authentication server.

The communication between the sender and receiver is secured using AES-GCM, with custom `sst_encrypt_gcm` and `sst_decrypt_gcm` implementations.

## Hardware Requirements

*   **Sender**:
    *   [Raspberry Pi Pico](https://www.sparkfun.com/raspberry-pi-pico.html?src=raspberrypi) (RP2040)
    *   Li-Fi transmitter compatible with the Pico
*   **Receiver**:
    *   [Raspberry Pi 4 Model B (4 GB)](https://www.sparkfun.com/raspberry-pi-4-model-b-4-gb.html?src=raspberrypi) (used for testing)
    *   Li-Fi receiver compatible with the Pi 4
*   **Connection**:
    *   Jumper wires to connect the Pico and Pi 4 via UART:
        *   Pico GP5 (Physical Pin 7) <-> Pi 4 GPIO14 (Physical Pin 8)

## Software Dependencies

*   **General**:
    *   CMake (version 3.13 or later)
    *   ARM GCC Compiler
    *   Java Development Kit (JDK)
    *   Maven
*   **Sender (Pico)**:
    *   [Pico SDK](https://github.com/raspberrypi/pico-sdk)
*   **Receiver (Pi 4)**:
    * The `iotauth` project is a dependency for provisioning keys; it may require OpenSSL. Check [here](https://github.com/iotauth/iotauth) for updates on how to properly use iotauth.
## Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd embedded
```

### 2. Pico SDK

Ensure the `PICO_SDK_PATH` environment variable is set to the location of your Pico SDK installation.

```bash
export PICO_SDK_PATH="/path/to/pico-sdk"
```

### 3. Setup `iotauth` Server & Credentials

The receiver requires credentials from the `iotauth` project, which also runs the authentication server.

**A. Generate Credentials**

1.  Navigate to the `iotauth` project directory. This guide assumes `sst-c-api` and `iotauth` are in the same parent directory.

    ```bash
    cd ../../iotauth/examples
    ```
2.  Run the credential generation scripts. You will be prompted to create and confirm a password.

    ```bash
    ./cleanAll
    ./generateAll
    ```
    You should see "generating credentials..." output.

**B. Run the Authentication Server**

1.  Navigate to the authentication server directory.

    ```bash
    cd ../auth/auth-server
    ```
2.  Build the server using Maven.

    ```bash
    mvn clean install
    ```
3.  Run the server. You will be prompted for the password you created earlier.

    ```bash
    java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
    ```
    The server is now running and listening for requests. Leave this terminal open.

**C. Update Receiver Credentials**

With the server running, you can now copy the generated credentials to the receiver project. This functionality will support caching the session key for intermittent WiFi connection in the future.

1.  In a new terminal, navigate back to the `receiver` directory in the `sst-c-api` project:

    ```bash
    cd /path/to/sst-c-api/embedded/receiver
    ```
2.  Update the `AUTH_PROJECT_ROOT` variable in `update-credentials.sh` to point to your `iotauth` project directory if it's not `../../../iotauth`.
3.  Run the script to copy the credentials:

    ```bash
    ./update-credentials.sh
    cd ..
    ```

## Building and Running

This guide provides the full workflow for building, flashing, and running the Li-Fi sender and receiver.

> **Note:** An application is being developed to control multiple Picos from a single USB-connected machine. The following steps are for manual, single-device testing.

### Step 1: Build the Sender (Pico)

1.  Ensure the `PICO_SDK_PATH` environment variable is set.
2.  Navigate to a build directory.
    ```bash
    mkdir -p build && cd build
    ```
3.  Run CMake and Make. This will automatically detect the Pico SDK and build the sender application.
    ```bash
    cmake ..
    make
    ```

### Step 2: Flash the Sender

Flash the `sender/lifi_sender_embedded.uf2` file from the build directory to your Pico.

### Step 3: Enable Pico Communication in WSL

To send messages to the Pico from a WSL environment, you need to attach the Pico's USB device to WSL.

1.  **List USB Devices:** Open a PowerShell or Command Prompt and use `usbipd` to list the available USB devices. Identify the BUSID for your Raspberry Pi Pico.
    ```powershell
    usbipd list
    ```
2.  **Attach to WSL:** Use the BUSID from the previous step to attach the Pico to WSL.
    ```powershell
    # Replace 1-3 with the actual BUSID of your Pico
    usbipd attach --busid 1-3 --wsl
    ```

### Step 4: Send a Message with `picocom`

1.  From your WSL terminal, use `picocom` to open a serial connection to the Pico. The device is typically `/dev/ttyACM0`.
    ```bash
    picocom /dev/ttyACM0
    ```
2.  You can now type messages in the `picocom` terminal and press Enter to send them over the Li-Fi connection.

### Step 5: Build and Run the Receiver

While the `picocom` session is active in one terminal, you will build and run the receiver in another.

1.  **Build the Receiver:**
    -   Navigate to a build directory (you can use the same one).
    -   Run CMake with the `-DHAS_PICO_SDK=OFF` flag to build the receiver application.
    ```bash
    # From the build directory
    cmake ..
    make
    ```
2.  **Run the Receiver:**
    -   Execute the `receiver_uart` program, providing the path to your `sst.config` file.
    ```bash
    # From the build directory
    ./receiver/receiver_uart ../receiver/sst.config
    ```
    The receiver will now listen for, decrypt, and display the messages you send from the Pico.
    In the future I plan to develop an app to communicate with multiple picos and send messages with drag and drop files, queries, and device-specific sharing of messages
