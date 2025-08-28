# Prerequisites

## Clone repository & Update submodule
```
$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
$ git submodule update --init
```

## Compilation of SST 
Please see the instructions [here](https://github.com/iotauth/sst-c-api?tab=readme-ov-file#compile).

## Create Example Auth Databases

1. Go to directory `$ROOT/examples`

2. Run `./generateAll.sh`
    - Run `./cleanAll.sh` if there are any errors or if you want a clean copy.

## Run Example Auth

1. Go to `$ROOT/auth/auth-server/`

2. Build the executable jar file by running `mvn clean install`

3. Run the jar file with the properties file for Auth101 with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

## Compile the scenario code

1. Go to `$ROOT/entity/c/examples/scenario_example/`

2. Run `mkdir build && cd build`
    - If you get `mkdir: build: File exists` then run `rm -rf build` and try again.

3. Run `cmake ..`
    - Run `cmake -DCMAKE_BUILD_TYPE=Debug ..` for debugging mode.

4. Run `make`





# How to Run the Basic Messaging Example

## Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`

2. *[Optional]* Customize `csv_files/basic_messages.csv` to have the client send custom messages to the server.
    - The format of the input CSV file for this example should be:
        - Each entry should be on its own line.
        - The amount of time spent sleeping (in milliseconds) is listed first.
        - The message is listed second.
        - The sleep time and message are always seperated by only a single comma.
    ```
    <sleep_time1>,<message1>
    <sleep_time2>,<message2>
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../../server_client_example/c_server.config`

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/basic_messages.csv`



# How to Run the Attack Examples

## Replay Attack Example

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`

2. *[Optional]* Customize `csv_files/replay_attack.csv` to have the client send custom messages and replay attacks to the server
    - The format of the input CSV file for this attack example should be:
        - Each entry should be on its own line.
        - Each value is separated using a comma.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type word, in this case it is "Replay".
            - The attack type word can also be written as "replay" or "REPLAY".
        - The fourth value is the sequence number change because this attack revolves around modifying the sequence number.
            - The formatting for changing the sequence number is "seq++", "seq--", or "seq=#" where # can be any integer.
    ```
    <sleep_time1>,<message1>,Replay,seq--
    <sleep_time2>,<message2>,REPLAY,seq++
    <sleep_time2>,<message2>,replay,seq=12
    ...
    ```

3. Run `cd build`.

4. Run the server with `./server ../../server_client_example/c_server.config`

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/replay_attack.csv`

## DoS Session Key Attack Example

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`

2. *[Optional]* Customize `csv_files/dos_attack_key.csv` to have the client send custom messages and DoS attacks to the server.
    - The format of the input CSV file for this attack example should be:
        - Each entry should be on its own line.
        - Each value is separated using a comma.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type word, in this case it is "DoSK".
            - The attack type word can also be written as "dosk" or "DOSK".
        - The fourth value is the number of session key requests the client will make to Auth.
    ```
    <sleep_time1>,<message1>,DoSK,10000
    <sleep_time2>,<message2>,DOSK,55555
    <sleep_time2>,<message2>,dosk,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../../server_client_example/c_server.config`

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/dos_attack_key.csv`

## DoS Server Connect Attack Example

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`

2. *[Optional]* Customize `csv_files/dos_attack_connect.csv` to have the client send custom messages and DoS attacks to the server.
    - The format of the input CSV file for this attack example should be:
        - Each entry should be on its own line.
        - Each value is separated using a comma.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type word, in this case it is "DoSC".
            - The attack type word can also be written as "dosc" or "DOSC".
        - The fourth value is the number of times the client should connect to the server using Auth.
    ```
    <sleep_time1>,<message1>,DoSC,10000
    <sleep_time2>,<message2>,DOSC,55555
    <sleep_time2>,<message2>,dosc,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../../server_client_example/c_server.config`

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/dos_attack_connect.csv`

## DoS Messaging Attack Example

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`

2. *[Optional]* Customize `csv_files/dos_attack_message.csv` to have the client send custom messages and DoS attacks to the server.
    - The format of the input CSV file for this attack example should be:
        - Each entry should be on its own line.
        - Each value is separated using a comma.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type word, in this case it is "DoSM".
            - The attack type word can also be written as "dosm" or "DOSM".
        - The fourth value is the number of times the message will be sent to the server.
    ```
    <sleep_time1>,<message1>,DoSM,10000
    <sleep_time2>,<message2>,DOSM,55555
    <sleep_time2>,<message2>,dosm,123456
    ...
    ```

3. Run `cd build`

4. Run the server with `./server ../../server_client_example/c_server.config`

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/dos_attack_connect.csv`




## Client DoS Attack Example
This attack involves using many clients to connect to the server to create the denial of service. To do that though, the Auth databases and configurations need to be modified to support this.

### Create New Graph for Auth Databases and Configuration Files for the Clients

1. Go to `$ROOT/entity/c/examples/scenario_example/clients_dos_attack`

2. Do `chmod +x clients_dos_setup.sh`

3. Run `./clients_dos_setup.sh <number-of-clients>`
    - `<number-of-clients>` is the maximum amount of clients that Auth should be able to recognize and is defined by the parameter.

4. Insert a password when prompted.

5. Run `./run_clients.sh <number-of-clients> <input-file>`
    - <number-of-clients> is the number of clients that should be created during this execution.
    - <input-file> is the input CSV file that the program should read for this execution.
        - The format of the file should match the corresponding format for each attack type given above because the attacks are the same, only that there are now multiple clients doing the attack simultaneously now.

Each client will be launched in a unique terminal window and will simultaneously perform the attack specified in the input CSV file.