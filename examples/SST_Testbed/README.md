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

4. Run the server with `./server server.config`

5. Run the client in another terminal with `./client client.config ../csv_files/basic_messages.csv`

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

4. Run the server with `./server server.config`

5. Run the client in another terminal with `./client client.config ../csv_files/replay_attack.csv`

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
    <sleep_time1>,<message1>,DoSK,10000
    <sleep_time2>,<message2>,DOSK,55555
    <sleep_time3>,<message3>,dosk,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server server.config`

5. Run the client in another terminal with `./client client.config ../csv_files/dos_attack_key.csv`

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
    <sleep_time1>,<message1>,DoSM,10000
    <sleep_time2>,<message2>,DOSM,55555
    <sleep_time3>,<message3>,dosm,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server server.config`

5. Run the client in another terminal with `./client client.config ../csv_files/dos_attack_message.csv`

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
    <sleep_time1>,<message1>,DoSC,10000
    <sleep_time2>,<message2>,DOSC,55555
    <sleep_time3>,<message3>,dosc,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server server.config`

5. Run the client in another terminal with `./client client.config ../csv_files/dos_attack_connect.csv`

## 2.2.4 DoS attack to Auth via SYN Flooding
1. Go to `$ROOT/entity/c/examples/SST_Testbed/`

2. *[Optional]* Customize `csv_files/dos_attack_syn.csv` to have the client send custom messages and a custom number of SYN packets to Auth.
    - The format of the input CSV file for this attack example should be:
        - Each entry is on its own line.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type, "DoSSYN" in this example (case insensitive).
        - The fourth value is the number SYN packets that will be sent to Auth.
    ```
    <sleep_time1>,<message1>,DoSSYN,10000
    <sleep_time2>,<message2>,DOSSYN,55555
    <sleep_time3>,<message3>,dossyn,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server server.config`

5. Run the client in another terminal with `./client client.config ../csv_files/dos_attack_syn.csv`


## 2.3 DoS attack with Multiple Clients (DDoS)
This attack involves using many clients to connect to the server to create the denial of service. To do that though, the Auth databases and configurations need to be modified to support this.
So, also make sure that the ***Auth*** executed before is terminated.

### Create New Graph for Auth Databases and Configuration Files for the Clients

1. Go to `$ROOT/entity/c/examples/SST_Testbed/clients_dos_attack`

2. *[Optional]* `chmod +x clients_dos_setup.sh`

3. Run `./clients_dos_setup.sh <number-of-clients> -p <password>`
    - `<number-of-clients>` is the maximum amount of clients that Auth should be able to recognize and is defined by the parameter.
    - *[Optional]* `<password>` is the password of the generated Auth.
    - e.g., `./client_dos_setup.sh 3 -p asdf`

4. Insert a password when prompted.

5. Run `./run_clients.sh <number-of-clients> <input-file>`
    - `<number-of-clients>` is the number of clients that should be created during this execution.
    - `<input-file>` is the input CSV file that the program should read for this execution.
        - The format of the file should match the corresponding format for each attack type given above because the attacks are the same, only that there are now multiple clients doing the attack simultaneously now.
        - e.g., `./run_clients.sh 3 ../csv_files/dos_attack_connect.csv `

Each client will be launched in a unique terminal window and will simultaneously perform the attack specified in the input CSV file.