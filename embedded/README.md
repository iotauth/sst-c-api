# 🔐 Secure Li-Fi Communication with SST

This project establishes secure, real-time Li-Fi communication between embedded edge devices using AES-GCM encryption and session keys provisioned by an SST-based authentication server.

---

## 🔧 Project Overview

This repository contains embedded software for secure Li-Fi communication, consisting of:

- **Sender (Raspberry Pi Pico)**: Encrypts user-input messages and transmits them via Li-Fi using AES-GCM and a session key.
- **Receiver (Raspberry Pi 4)**: Fetches session keys from the SST Auth server, transmits them to the Pico via UART, and receives and decrypts Li-Fi messages from the Pico.

### Key Features:
- AES-GCM encryption using `sst_encrypt_gcm()` and `sst_decrypt_gcm()`
- Flash memory storage for session key persistence on the Pico
- Command interface over UART with support for:
  - `CMD: print key sender`
  - `CMD: print key receiver`
  - `CMD: print key *`
  - `CMD: rotate key`
  - `CMD: clear key`
  - `CMD: reboot`
- Smart flash logic: Pico clears flash when needed and waits for valid keys

---

## 🔧 Hardware Requirements

### **Sender (Pico)**
- [Raspberry Pi Pico (RP2040)](https://www.sparkfun.com/raspberry-pi-pico.html?src=raspberrypi)
- Li-Fi LED transmitter module
- USB cable (for programming and debug serial)

### **Receiver (Pi 4)**
- [Raspberry Pi 4 Model B (4 GB)](https://www.sparkfun.com/raspberry-pi-4-model-b-4-gb.html?src=raspberrypi)
- Li-Fi receiver module

### **Connection (UART1)**
- **Pico TX (GPIO 4)** → **Pi 4 RX (GPIO14, Pin 8)**
- **Pico RX (GPIO 5)** ← **Pi 4 TX (GPIO15, Pin 10)**

---

## 📦 Software Dependencies

- CMake ≥ 3.13
- ARM GCC Toolchain
- Java (for SST server)
- Maven (for SST server)
- [Pico SDK](https://github.com/raspberrypi/pico-sdk)

### SST Software
- [iotauth](https://github.com/iotauth/iotauth) project (used for key provisioning)
- [sst-c-api](https://github.com/iotauth/sst-c-api) (included as a submodule or dependency)

---

## 🛠️ Setup Instructions

### 1. Clone the Repository with Submodules
```bash
git clone --recurse-submodules <repo-url>
cd embedded
```

### 2. Export `PICO_SDK_PATH`
```bash
export PICO_SDK_PATH=/path/to/pico-sdk
```

---

## 🔑 SST Server Setup (Key Provisioning)

### A. Generate Credentials
```bash
cd ../../iotauth/examples
./cleanAll
./generateAll
```

### B. Run the Authentication Server
```bash
cd ../auth/auth-server
mvn clean install
java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

### C. Copy Credentials to Receiver
```bash
cd /path/to/sst-c-api/embedded/receiver
./update-credentials.sh
cd ..
```

---

## ⚙️ Building and Flashing

### 1. Build Sender Firmware
```bash
cd embedded
mkdir build && cd build
cmake ..
make
```

### 2. Flash the Pico
Copy `sender/lifi_sender_embedded.uf2` to the Pico USB device.

---

## 🔌 USB & UART in WSL (Optional)

To use UART in WSL:

```powershell
usbipd list
usbipd attach --busid <BUSID> --wsl
```

Then:
```bash
picocom /dev/ttyACM0
```

---

## 🛜 Running Receiver

From a separate terminal:

```bash
./receiver/receiver_uart ../receiver/sst.config
```

---

## 💬 Command Interface

Send commands over UART0 (debug) on the Pico:

| Command                    | Action |
|---------------------------|--------|
| `CMD: print key sender`   | Prints key on Pico, receiver confirms |
| `CMD: print key receiver` | Prints key on Pi 4, Pico confirms |
| `CMD: print key *`        | Prints keys on both |
| `CMD: rotate key`         | Receiver sends new session key |
| `CMD: clear key`          | Clears key from Pico flash |
| `CMD: reboot`             | Reboots the Pico |

---

## 🧪 Notes & Future Work

- Pico startup waits up to 10 seconds for a valid session key on fresh boot.
- If a session key is stored in flash, it will load and use it immediately.
- Future work may include:
  - GUI desktop app to manage multiple Picos
  - File transfer support
  - Federated authentication caching
  - TPM integration for secure key storage on Pi 4

---