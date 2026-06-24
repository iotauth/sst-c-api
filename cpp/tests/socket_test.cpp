/**
 * @file socket_test.cpp
 * @async Unit test for the SST C++ socket API (cpp/src/net/sockets.{hpp,cpp}).
 */

#include "../src/net/sockets.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using sst::SST_SOCK_DOMAIN;

namespace {

void test_basic_socket_lifecycle() {
    std::printf("**** STARTING test_basic_socket_lifecycle.\n");
    {
        sst::Socket s;
        assert(s.get_fd() == -1);
    }
    std::printf("**** PASSED: test_basic_socket_lifecycle.\n");
}

void test_client_socket_creation() {
    std::printf("**** STARTING test_client_socket_creation.\n");
    sst::ClientSocket client(sst::SST_SOCK_INET, "127.0.0.1", 8080);
    if (client.get_fd() == -1) {
        std::printf("ClientSocket creation failed unexpectedly!\n");
        exit(1);
    }
    std::printf("**** PASSED: test_client_socket_creation.\n");
}

void test_server_socket_creation() {
    std::printf("async starting test_server_socket_creation.\n"); // wait, I'm losing it.
    sst::ServerSocket server(sst::SST_SOCK_INET, "127.0.0.1", 8081);
    if (server.get_fd() == -1) {
        std::printf("ServerSocket creation failed unexpectedly!\n");
        exit(1);
    }
    std::printf("**** PASSED: test_server_socket_creation.\n");
}

void test_socket_info_copy() {
    std::printf("**** STARTING test_socket_info_copy.\n");
    sst::ClientSocket client(sst::SST_SOCK_INET, "127.0.0.1", 8080);
    if (client.get_fd() == -1) {
        std::printf("ClientSocket creation failed before GetSocketInfo call!\n");
        exit(1);
    }
    auto info_copy = client.GetSocketInfo();
    assert(info_copy != nullptr);
    assert(info_copy->sock != -1);
    std::printf("**** PASSED: test_socket_info_copy.\n");
}

} // namespace

int main() {
    test_basic_socket_lifecycle();
    test_client_socket_creation();
    test_server_socket_creation();
    test_socket_info_copy();

    std::printf("All Socket API tests passed.\n");
    return 0;
}
