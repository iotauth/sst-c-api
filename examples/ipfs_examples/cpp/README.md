# How to Run Example

## Prerequisites

## Clone repository & Update submodule
```
$ git clone https://github.com/iotauth/iotauth.git
$ cd iotauth
$ git submodule update --init
```

## Installation of SST as Shared Library
Please see the instructions [here](https://github.com/iotauth/sst-c-api?tab=readme-ov-file#compile-as-shared-library).

### Create Example Auth Databases

1. Go to directory `$ROOT/examples`.

2. Run `./generateAll.sh -g configs/file_sharing.graph`.

3. Run `./cleanAll.sh` if there are any errors or if you want a clean copy.

### Run IPFS

1. [Install IPFS](https://docs.ipfs.tech/install/command-line/#install-official-binary-distributions). Also run `ipfs init` on the first time starting ipfs.

2. Run `ipfs daemon`.

### Run Example Auth

1. Go to `$ROOT/auth/auth-server/`.

2. Build the executable jar file by running `mvn clean install`.

3. Run the jar file with the properties file for Auth101 with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`.

### Run Example File System Manager

1. Go to `$ROOT/examples/file_sharing/`.

2. Run `python3 file_system_manager.py`.

## Run the Example Entities

1. Go to `$ROOT/entity/c/examples/ipfs_examples/` and create a `plain_text` file.
    - Enter any text into the file and save.

2. Run `cd cpp`.

3. Run `mkdir build && cd build`.
    - If you get `mkdir: build: File exists` then run `rm -rf build`.

4. Run `cmake ..`.
    - Run `cmake -DCMAKE_BUILD_TYPE=Debug ..` for debugging mode.

5. Run `make`.

6. Run `./uploader ../../uploader.config ../../plain_text ../../addReader.txt`.

7. Once `Waiting for client to connect...` is printed in the Terminal, run the downloader in another terminal with `./downloader ../../downloader.config`.

8. Once downloader finishes running, uploader resumes. Once the hashes are compared at the end, uploader has finished running.