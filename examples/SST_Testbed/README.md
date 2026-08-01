# SST Testbed

Award-winning testing tool! [1st Place Winner in ESSC at ESWEEK 2025](https://2025.esweek.org/awards-2025/)

# Directory Structure

- `clients_dos_attack/`

    Contains the scripts for creating the environment for launching the attacks with multiple clients.

- `csv_files/`

    Contains the CSV files passed when executing the testbed that are used to specify the attack type.

- `lib/`

    Contains the files used for tracking the metrics of the DDoS attacks.

- `metric_logs/`

    Folder for storing the metric logs that are created.

- `plot_generators/`

    Contains `plot.py` which generates plots for the attack metrics when given metric logs.

SST Testbed is an open-source, extensible platform for evaluating the security and resilience of embedded, resource-constrained networked systems. It supports replay and denial-of-service (DoS) attacks, including distributed variants, through configurable CSV input files and lightweight scripts that simplify setup and experimentation. Notably, SST Testbed won [1st place](https://2025.esweek.org/awards-2025/) in the [Embedded System Software Competition (ESSC)](https://embedded-research-competition.github.io/) at [ESWEEK 2025](https://2025.esweek.org/).

> **Publication:** C. Beltran Quinonez, D. Kim, and H. Kim, "SST Testbed: An Experimental Platform of Attacks and Defenses for Networked Embedded Systems," in *Proc. 2026 IEEE International Conference on Industrial Technology (ICIT)*, 2026.
> DOI: [10.1109/ICIT64854.2026.11490150](https://ieeexplore.ieee.org/document/11490150)

---

# Background

## Overview

The growing prevalence of IoT devices has introduced significant security challenges, as their constant connectivity and limited resources make them vulnerable to network-level attacks. SST Testbed addresses the lack of open-source security testbeds designed for constrained environments by providing a practical, reproducible environment for attack simulation and defense evaluation.

SST Testbed builds upon the [Secure Swarm Toolkit (SST)](https://github.com/iotauth/iotauth) using the C API. SST introduces a local authorization entity, **Auth**, that acts as a Key Distribution Center (KDC), providing authentication and authorization services for connected devices.

## Workflow

The testbed workflow is organized into five stages:

![SST Testbed Workflow](images/fig1_workflow.png)

1. **Setup** — The user specifies the number of clients and attack type via an input CSV file, then runs `clients_dos_setup.sh` to initialize the environment.
2. **Generate Testbed** — `graph_generator.js` produces the network topology; `config_generator.js` creates per-entity configuration files (credential paths, Auth IP/port, Auth ID, entity name).
3. **Execution** — `run_clients.sh` launches the specified number of clients and the server, each loading its configuration file.
4. **Network Attack Simulation** — Clients carry out attack scenarios defined in the CSV (replay, excessive key requests, message flooding, repeated connections).
5. **Deployment** — The generated artifacts can run in simulation (ns-3) or be deployed directly to embedded devices such as Raspberry Pi boards without modifying attack logic.

## Supported Attacks

### Replay Attack

The user manipulates the sequence number attached to each client message. Changing the sequence number simulates replaying a previous message to confuse or manipulate the server. The CSV parameter specifies the sequence number modification (`seq++`, `seq--`, `seq=N`).

### DoS / DDoS via Session Key Requests (DoSK)

Clients issue an excessive number of session key requests to the Auth/KDC, exhausting its key-provisioning capacity and preventing legitimate clients from obtaining keys.

![DoSK — Clients launching excessive session key requests toward the Auth/KDC](images/fig2_ddos_key.png)

### DoS / DDoS via Message Flooding (DoSM)

Once a session is established, clients flood the server with a large volume of secure messages, overwhelming its message-handling loop and network buffers.

![DoSM — Clients overwhelming the server with a large volume of secure messages](images/fig3_ddos_message.png)

### DoS / DDoS via Connection Requests (DoSC)

Clients repeatedly connect to the server, consuming its CPU and memory for session management. Each connection also triggers a session key request to Auth, amplifying load on both the server and Auth.

![DoSC — Clients repeatedly connecting to the server, indirectly triggering excessive session key requests to Auth](images/fig4_ddos_connect.png)

### DoS / DDoS via SYN Flooding

Unlike the attacks above, a SYN flood requires no authentication. The attacker sends a large number of TCP SYN packets without completing the handshake, filling the target's connection table with half-open entries. A botnet can amplify this into a DDoS by distributing SYN streams across many sources.

## Experimental Setup and Results

The testbed was evaluated across three hardware configurations:

| Config | Auth | Server | Benign Client | Attacker |
|--------|------|--------|---------------|----------|
| #1 | Workstation | Workstation | Workstation 2 | MacBook Pro |
| #2 | Workstation | RPI 4B #1 | RPI 4B #2 | RPI 4B #3 |
| #3 | Workstation | RPI 4B #1 | RPI 4B #2 | RPI 4B #3 + MacBook Pro |

![Config #3 deployment topology](images/fig5_deployment.png)

### DDoS Key Attack Results
Benign client latency grows linearly up to **85x** and throughput drops up to **98.9%** as malicious clients increase from 0 to 100.

![DDoS Key Attack — Latency and Throughput](images/fig6_key_results.png)

### DDoS Message Attack Results
Latency increases up to **301x** and throughput decreases up to **99.99%**.

![DDoS Message Attack — Latency and Throughput](images/fig7_message_results.png)

### DDoS Connect Attack Results
Latency increases up to **9.6x** and throughput decreases up to **98.8%**. With 100 attackers, 90 out of 100 benign connection attempts failed.

![DDoS Connect Attack — Latency and Throughput](images/fig8_connect_results.png)

### DDoS SYN Flood Results
Latency increased up to **6.0x** and throughput decreased up to **82.7%**. No key-request failures were observed.

![DDoS SYN Flood — Latency and Throughput](images/fig9_syn_flood_results.png)

---

# Prerequisites
### ***Auth***
1. OpenSSL command line tools for creating certificates and keystores of Auths and example entities
2. Java 11 or above
3. [Maven CLI (command line interface)](http://maven.apache.org/ref/3.1.0/maven-embedder/cli.html) for building Auth from the command line
4. Node.js for running example server and client entities
### `sst-c-api`
1. OpenSSL 3.0 or above
2. CMake 3.19 or above
## Installation
### Debian/Ubuntu
```
sudo apt-get update && sudo apt-get install -y \
    openjdk-11-jdk \
    maven \
    nodejs \
    npm \
    openssl \
    cmake \
    build-essential \
    pkg-config \
    libssl-dev
```
---
### MacOS
```
brew install openjdk@11 maven node openssl cmake pkg-config
```

## Verify versions
```
java -version
mvn -version
node -v
openssl version
cmake --version
```

## Clone repository & Update submodule
```
$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
$ git submodule update --init
```

# Compilation

### Compilation of Auth

1. Go to directory `iotauth/examples`

### Compile the SST_Testbed code

1. Go to `iotauth/entity/c/examples/SST_Testbed/`

2. Run `mkdir build && cd build`

3. Run `cmake ..`
    - Run `cmake -DCMAKE_BUILD_TYPE=Debug ..` for debugging mode.

4. Run `make`

# Running Examples
We have multiple examples to run.
1. Basic messaging examples with no attacks.
2. Attack scenarios
    - **2.1** Replay attack
    - **2.2** Denial of Service (DoS) attacks
        - **2.2.1** to Auth via session key requests (DoSK)
        - **2.2.2** to server via sending messages (DoSM)
        - **2.2.3** to server, and indirectly to Auth via connection requests (DoSC)
    - **2.3** Denial of Service (DoS) attacks with multiple clients
        - **2.3.1** DDoSK
        - **2.3.2** DDoSM
        - **2.3.3** DDoSC

We clarify that all examples need the Auth, to distribute keys, so launching the Auth once in one terminal will cover from Basic messaging examples, to DoS attacks.
However, for convenience, DoS attacks with multiple clients have it's own script to launch the Auth and clients.

### Running the Auth
1. Go to `$ROOT/auth/auth-server/`

2. Build the executable jar file by running `mvn clean install`

3. Run the jar file with the properties file for Auth101 with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

## 1. Basic Messaging

1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/basic_messages.csv` to have the client send custom messages to the server.
    - The format of the input CSV file for this example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The sleep time and message are always seperated by only a single comma.
    ```
    <sleep_time1>,<message1>
    <sleep_time2>,<message2>
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../config/server.config`

5. Run the client in another terminal with `./client ../config/client.config ../csv_files/basic_messages.csv`

## 2. Attack Scenarios
## 2.1 Replay Attack

1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/replay_attack.csv` to have the client send custom messages and replay attacks to the server,
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "Replay" in this example (case insensitive).
        - Fourth, is the sequence number change because this attack revolves around modifying the sequence number.
            - The formatting for changing the sequence number is "seq++", "seq--", or "seq=#" where # can be any integer.
    ```
    <sleep_time1>,<message1>,Replay,seq--
    <sleep_time2>,<message2>,REPLAY,seq++
    <sleep_time3>,<message3>,replay,seq=12
    ...
    ```

3. Run `cd build`.

4. Run the server with `./server ../config/server.config`

5. Run the client in another terminal with `./client ../config/client.config ../csv_files/replay_attack.csv`

## 2.2 Denial of Service (DoS) attack
## 2.2.1 DoS attack to Auth via session key requests (DoSK)

1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/dos_attack_key.csv` to have the client send custom messages and a custom number of session key requests to Auth.
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "DoSK" in this example (case insensitive).
        - The fourth value is the number of session key requests the client will send to Auth.
    ```
    <sleep_time1>,<message1>,DoSK,<number_of_key_requests>
    <sleep_time2>,<message2>,DOSK,<number_of_key_requests>
    <sleep_time3>,<message3>,dosk,<number_of_key_requests>
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../config/server.config`

5. Run the client in another terminal with `./client ../config/client.config ../csv_files/dos_attack_key.csv`

## 2.2.2 DoS attack to Server via Messages (DoSM)

1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/dos_attack_message.csv` to have the client send custom messages and a custom number of messages to the server.
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "DoSM" in this example (case insensitive).
        - The fourth value is the number of times the message will be sent to the server.
    ```
    <sleep_time1>,<message1>,DoSM,<number_of_messages>
    <sleep_time2>,<message2>,DOSM,<number_of_messages>
    <sleep_time3>,<message3>,dosm,<number_of_messages>
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../config/server.config`

5. Run the client in another terminal with `./client ../config/client.config ../csv_files/dos_attack_message.csv`

## 2.2.3 DoS attack to Server and Auth via connection requests (DoSC)

1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/dos_attack_connect.csv` to have the client send custom messages and a custom number of connection attempts to the server.
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "DoSC" in this example (case insensitive).
        - The fourth value is the number of connection attempts.
    ```
    <sleep_time1>,<message1>,DoSC,<number_of_connection_attemps>
    <sleep_time2>,<message2>,DOSC,<number_of_connection_attemps>
    <sleep_time3>,<message3>,dosc,<number_of_connection_attemps>
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../config/server.config`

5. Run the client in another terminal with `./client ../config/client.config ../csv_files/dos_attack_connect.csv`

## 2.2.4 DoS attack to Auth or Server via SYN Flooding (DoSS)
1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/dos_attack_syn.csv` to have the client send custom messages and a custom number of SYN packets to Auth or Server.
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "DoSS" in this example (case insensitive).
        - The fourth value is the number SYN packets that will be sent.
        - The fifth value is the target (Auth or Server).
    ```
    <sleep_time1>,<message1>,DoSS,<number_of_syn_packets>,Auth
    <sleep_time2>,<message2>,DOSS,<number_of_syn_packets>,a
    <sleep_time3>,<message3>,doss,<number_of_syn_packets>,server
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../config/server.config`

5. Run the client in another terminal with `sudo ./client ../config/client.config ../csv_files/dos_attack_syn.csv`

## 2.2.5 DoS attack to Auth or Server via UDP Flooding (DoSU)
1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/dos_attack_udp.csv` to have the client send custom messages and a custom number of UDP packets to Auth or Server.
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "DoSU" in this example (case insensitive).
        - The fourth value is the number UDP packets that will be sent to Auth or Server.
    ```
    <sleep_time1>,<message1>,DoSU,<number_of_udp_packets>,Server
    <sleep_time2>,<message2>,DOSU,<number_of_udp_packets>,S
    <sleep_time3>,<message3>,dosu,<number_of_udp_packets>,auth
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../config/server_udp.config`

5. Run the client in another terminal with `sudo ./client ../config/client_udp.config ../csv_files/dos_attack_udp.csv`


## 2.3 DoS attack with Multiple Clients (DDoS)
This attack involves using many clients to connect to the server to create the denial of service. To do that though, the Auth databases and configurations need to be modified to support this.
So, also make sure that the ***Auth*** executed before is terminated.

### Create New Graph for Auth Databases and Configuration Files for the Clients

1. Go to `$ROOT/entity/c/examples/SST_Testbed/clients_dos_attack`

2. *[Optional]* `chmod +x clients_dos_setup.sh`

3. Run `./clients_dos_setup.sh <number_of_clients> [password]`
    - `<number_of_clients>` is the maximum amount of clients that Auth should be able to recognize and is defined by the parameter.
    - `[password]` is optional. If provided, it is used as the password of the generated Auth.
    - e.g., `./clients_dos_setup.sh 3` or `./clients_dos_setup.sh 3 asdf`

4. If password is not provided, insert a password when prompted.

5. Run `./run_clients.sh <number_of_clients> <input_file> [-metrics] [source-ip]`
    - `<number_of_clients>` is the number of clients that should be created during this execution.
    - `<input_file>` is the input CSV file that the program should read for this execution.
        - The format of the file should match the corresponding format for each attack type given above because the attacks are the same, only that there are now multiple clients doing the attack simultaneously now.
        - `[-metrics]` is optional. If provided, each client writes metrics to `SST_Testbed/metric_logs/`.
        - `[source-ip]` is optional. If provided, it is forwarded to each client after `-metrics`, matching the client's expected argument order.
        - e.g., `./run_clients.sh 3 ../csv_files/dos_attack_connect.csv`
        - e.g., `./run_clients.sh 3 ../csv_files/dos_attack_connect.csv -metrics`
        - e.g., `./run_clients.sh 3 ../csv_files/dos_attack_connect.csv -metrics 192.168.1.10`

Each client will be launched in a unique terminal window, along with a terminal window for the server, and will simultaneously perform the attack specified in the input CSV file.
