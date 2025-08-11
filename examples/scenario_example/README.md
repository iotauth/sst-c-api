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

1. Go to directory `$ROOT/examples`.

2. Run `./generateAll.sh`.
    - Run `./cleanAll.sh` if there are any errors or if you want a clean copy.

## Run Example Auth

1. Go to `$ROOT/auth/auth-server/`.

2. Build the executable jar file by running `mvn clean install`.

3. Run the jar file with the properties file for Auth101 with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`.

## Compile the scenario code

1. Go to `$ROOT/entity/c/examples/scenario_example/`.

2. Run `mkdir build && cd build`.
    - If you get `mkdir: build: File exists` then run `rm -rf build` and try again.

3. Run `cmake ..`.
    - Run `cmake -DCMAKE_BUILD_TYPE=Debug ..` for debugging mode.

4. Run `make`.



# How to Run the Basic Messaging Example

## Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`.

2. *[Optional]* Customize `csv_files/basic_messages.csv` to have client send custom messages to the server.
    - Format of the csv should be:
        - Each entry should be on its own line.
        - The amount of time spent sleeping (in milliseconds) is listed first.
        - The message is listed second.
        - The sleep time and message are always seperated by only a single comma.
    ```
    <sleep_time1>,<message1>
    <sleep_time2>,<message2>
    ...
    ```

3. Run `cd build`.

4. Run the server with `./server ../../server_client_example/c_server.config`.

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/basic_messages.csv`.



# How to Run the Attack Examples

## Replay Attack Example

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`.

2. *[Optional]* Customize `csv_files/replay_attack.csv` to have client send custom messages and replay attacks to the server.
    - Format of the csv should be:
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

4. Run the server with `./server ../../server_client_example/c_server.config`.

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/replay_attack.csv`.

## SKey DoS Attack Example

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`.

2. *[Optional]* Customize `csv_files/dos_attack_key.csv` to have client send custom messages and dos attacks to the server.
    - Format of the csv should be:
        - Each entry should be on its own line.
        - Each value is separated using a comma.
        - The first value is the amount of time spent sleeping (in milliseconds).
        - The second value is the message.
        - The third value is the attack type word, in this case it is "DoS".
            - The attack type word can also be written as "dos" or "DOS".
        - The fourth value is the number of requests the client should make to Auth.
    ```
    <sleep_time1>,<message1>,Replay,10000
    <sleep_time2>,<message2>,REPLAY,55555
    <sleep_time2>,<message2>,replay,123456
    ...
    ```

3. Run `cd build`.

4. Run the server with `./server ../../server_client_example/c_server.config`.

5. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../csv_files/dos_attack_key.csv`.

## Client DoS Attack Example
This attack involves using many clients to connect to the server to create the denial of service. To do that though, the Auth databases and configurations need to be modified to support this.

### Create New Graph for Auth Databases

1. Go to `$ROOT/entity/c/examples/scenario_example/client_dos_attack`.

2. Run `node graph_generator.js <count>`
    - It has one required argument. It is the custom number of clients the Auth should be able to accept.

### Create Example Auth Databases

After running `graph_generator.js`, the Auth databases must be regenerated using the new client count.

1. Go to directory `$ROOT/examples`.

2. Run `./generateAll.sh -g configs/custom_clients.graph`.
    - Run `./cleanAll.sh` if there are any errors or if you want a clean copy.

### Run Example Auth
Make sure to [Run Example Auth](##run-example-auth) again since the the Auth databases have been regenerated.

### Run the Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/client_dos_attack`.

2. Run `./config_and_clients.sh <count>`
    - This will create the config files in `scenario_example/config`, run a server, and run the specified number of clients in different terminal tabs simultaneously.
    - `<count>` specifies the number of config files to create and the number of clients to run.
