cmake_minimum_required(VERSION 3.10)

project(scenario_example)

add_executable(server server.cpp)
add_executable(client client.cpp)

target_include_directories(server PRIVATE ../../..)
target_include_directories(client PRIVATE ../../..)

target_link_directories(server PRIVATE ../../build /opt/homebrew/opt/openssl/lib)
target_link_directories(client PRIVATE ../../build /opt/homebrew/opt/openssl/lib)

target_link_libraries(server PRIVATE crypto sst-c-api)
target_link_libraries(client PRIVATE crypto sst-c-api)
