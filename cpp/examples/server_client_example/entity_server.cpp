/**
 * @file entity_server.cpp
 * @brief Entity server example built on the SST C++ API.
 *
 * C++ counterpart of examples/server_client_example/entity_server.c. It
 * listens with the SST C++ socket layer, accepts two clients in turn, runs
 * the session key handshake for each, exchanges a few secure messages and
 * exits. The session key list is shared between the two connections so a
 * key received for the first client is reused if the second one presents the
 * same key ID.
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "../../src/api.hpp"
#include "../../src/net/sockets.hpp"

namespace {

// Reads secure messages until the client closes the connection (or the
// session is shut down) and prints them.
void receive_messages(sst::SST_Session& session) {
    unsigned char data_buf[sst::MAX_SECURE_COMM_MSG_LENGTH];
    while (true) {
        int len = session.read_secure_message(data_buf, sizeof(data_buf));
        if (len < 0) {
            std::fprintf(stderr, "Failed to read_secure_message().\n");
            return;
        }
        if (len == 0) {
            return;
        }
        std::printf("Received: %.*s\n", len, data_buf);
        std::fflush(stdout);
    }
}

int accept_client(sst::ServerSocket& server) {
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    // reinterpret_cast: required by the POSIX accept() signature.
    int clnt_sock =
        accept(server.get_fd(), reinterpret_cast<struct sockaddr*>(&clnt_addr),
               &clnt_addr_size);
    if (clnt_sock == -1) {
        std::fprintf(stderr, "accept() error.\n");
        std::exit(1);
    }
    return clnt_sock;
}

void send_or_exit(sst::SST_Session& session, const char* msg) {
    if (session.send_secure_message(msg) < 0) {
        std::fprintf(stderr, "Failed send_secure_message().\n");
        std::exit(1);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <config_file_path>\n", argv[0]);
        return 1;
    }
    using std::chrono::seconds;
    try {
        sst::SST_API api(argv[1]);
        const int port = api.get_config().entity_server_port_num;

        // Bind and listen with the SST C++ socket API. The listener is
        // closed automatically when it goes out of scope (RAII).
        sst::ServerSocket server(sst::SST_SOCK_INET, "0.0.0.0", port);
        if (server.get_fd() == -1) {
            std::fprintf(stderr, "Failed to open server socket on port %d\n",
                         port);
            return 1;
        }
        std::printf("Entity server listening on port %d...\n", port);
        std::fflush(stdout);

        sst::SessionKeyList s_key_list;

        // First connection.
        {
            int clnt_sock = accept_client(server);
            auto session = api.server_secure_comm_setup(clnt_sock, s_key_list);
            std::thread receiver(receive_messages, std::ref(*session));
            std::this_thread::sleep_for(seconds(1));
            send_or_exit(*session, "Hello client");
            std::this_thread::sleep_for(seconds(1));
            send_or_exit(*session, "Hello client - second message");
            std::this_thread::sleep_for(seconds(2));
            // Unblock the receiver thread, then close the session.
            session->shutdown();
            receiver.join();
            std::printf("Finished first communication\n");
            std::fflush(stdout);
        }

        // Second connection. s_key_list caches the session keys.
        {
            int clnt_sock2 = accept_client(server);
            auto session2 =
                api.server_secure_comm_setup(clnt_sock2, s_key_list);
            std::thread receiver2(receive_messages, std::ref(*session2));
            std::this_thread::sleep_for(seconds(1));
            send_or_exit(*session2, "Hello client 2");
            std::this_thread::sleep_for(seconds(1));
            send_or_exit(*session2, "Hello client 2 - second message");
            std::this_thread::sleep_for(seconds(4));
            session2->shutdown();
            receiver2.join();
            std::printf("Finished second communication\n");
            std::fflush(stdout);
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
