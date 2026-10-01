/**
 * @file entity_client.cpp
 * @brief Entity client example built on the SST C++ API.
 *
 * C++ counterpart of examples/server_client_example/entity_client.c. It
 * requests session keys from Auth, connects to the entity server twice (with
 * two different session keys), and exchanges a few secure messages on each
 * connection.
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "../../src/api.hpp"

namespace {

// Reads secure messages until the server closes the connection (or the
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

        sst::SessionKeyList s_key_list = api.get_session_key();
        if (s_key_list.size() < 2) {
            std::fprintf(stderr,
                         "Expected at least two session keys, got %d.\n",
                         s_key_list.size());
            return 1;
        }

        // First connection with the first session key.
        {
            auto session = api.secure_connect_to_server(s_key_list.s_key[0]);
            std::this_thread::sleep_for(seconds(1));
            std::thread receiver(receive_messages, std::ref(*session));
            send_or_exit(*session, "Hello server");
            std::this_thread::sleep_for(seconds(1));
            send_or_exit(*session, "Hello server - second message");
            std::this_thread::sleep_for(seconds(1));
            session->shutdown();
            receiver.join();
        }

        std::this_thread::sleep_for(seconds(3));

        // Second connection with the second session key.
        {
            auto session = api.secure_connect_to_server(s_key_list.s_key[1]);
            std::thread receiver(receive_messages, std::ref(*session));
            send_or_exit(*session, "Hello server 2");
            std::this_thread::sleep_for(seconds(1));
            send_or_exit(*session, "Hello server 2 - second message");
            std::this_thread::sleep_for(seconds(3));
            session->shutdown();
            receiver.join();
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
