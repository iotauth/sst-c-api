# How to Run Example

## Prerequisites

### Clone repository & Update submodule
```
$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
$ git submodule update --init
```

### Compilation of SST 
Please see the instructions [here](https://github.com/iotauth/sst-c-api?tab=readme-ov-file#compile).

### Create Example Auth Databases

1. Go to directory `$ROOT/examples`.

2. Run `./generateAll.sh`.
    - Run `./cleanAll.sh` if there are any errors or if you want a clean copy.

### Run Example Auth

1. Go to `$ROOT/auth/auth-server/`.

2. Build the executable jar file by running `mvn clean install`.

3. Run the jar file with the properties file for Auth101 with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`.

### Run Example File System Manager

1. Go to `$ROOT/examples/file_sharing/`.

2. Run `python3 file_system_manager.py`.

## Run the Example Entities

1. Go to `$ROOT/entity/c/examples/scenario_example/`.

2. *[Optional]* Modify `example_messages.csv` to have client send custom messages to the server.
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

3. Run `mkdir build && cd build`.
    - If you get `mkdir: build: File exists` then run `rm -rf build` and try again.

4. Run `cmake ..`.
    - Run `cmake -DCMAKE_BUILD_TYPE=Debug ..` for debugging mode.

5. Run `make`.

6. Run the server with `./server ../../server_client_example/c_server.config`.

7. Run the client in another terminal with `./client ../../server_client_example/c_client.config ../messages.csv`.