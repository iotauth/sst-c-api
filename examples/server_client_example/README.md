# Compile
We use $SST_ROOT for the root directory of [SST's main repository](https://github.com/iotauth/iotauth/).

```
$cd $SST_ROOT/entity/c/examples/server_client_example
$mkdir build && cd build
$cmake ../
$make
```

# Example 1

- Turn on a Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a server terminal at `$SST_ROOT/entity/c/examples/server_client_example/build`
- Turn on a client terminal at `$SST_ROOT/entity/c/examples/server_client_example/build`

Execute
Auth Terminal 
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Client Terminal
`$ ./entity_server ../c_server.config`
`$ ./entity_client ../c_client.config`

# Example 2
  Gets multiple session keys, and save the IDs to a metadata file respectively.

- Turn on a Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a terminal at `$SST_ROOT/entity/c/examples/server_client_example/build`

Execute
Auth Terminal 
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Other Terminal
`$ ./threaded_get_target_id_client ../c_client.config`
`$ ./threaded_get_target_id_server ../c_server.config`

# Example 3
  Use a permanent distribution key instead of using PKI. 
  When running `./generateAll.sh`, the graph file should configure the entity as `"usePermanentDistKey": false,` to create permanent distribution keys instead PKI certificates.


 - Turn on a Auth terminal at `$SST_ROOT/auth/auth-server`
- Turn on a server terminal at `$SST_ROOT/entity/c/examples/server_client_example/build`
- Turn on a client terminal at `$SST_ROOT/entity/c/examples/server_client_example/build`

Execute
Auth Terminal 
`$ java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`

Client Terminal
`$ ./entity_server ../c_rc_server.config`
`$ ./entity_client ../c_rc_client.config`