## Turn on Auth

```
$ cd iotauth/auth/auth-server
$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties
```

## Build tests
```
$ cd iotauth/entity/c/tests
$ mkdir build && cd build
$ cmake ../
$ make
```

## Execute tests
```
$ ./TEST ../client.config
```