/**
 * @file secure_ipfs_server.cpp
 * @brief Secure IPFS server example built on the SST C++ socket API.
 *
 * The TCP listener uses the C++ RAII socket layer (sst::ServerSocket). The
 * SST secure session itself still uses the C API: the C++ API does not
 * implement server-side secure communication yet.
 */

#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>

#include "../../src/net/sockets.hpp"

extern "C" {
#include "../../../src/c_api.h"
}

namespace {

constexpr int PORT_NUM = 21100;

void* receive_thread(void* arg) {
    SST_session_ctx_t* session_ctx = static_cast<SST_session_ctx_t*>(arg);
    unsigned char buffer[MAX_SECURE_COMM_MSG_LENGTH];
    int recv_len;

    while ((recv_len = read_secure_message(buffer, session_ctx)) > 0) {
        std::printf("Received %d bytes from client\n", recv_len);
    }

    return nullptr;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error_exit("Usage: %s <config_file_path>", argv[0]);
    }

    // Bind and listen with the SST C++ socket API. The listener is closed
    // automatically when it goes out of scope (RAII).
    sst::ServerSocket server(sst::SST_SOCK_INET, "0.0.0.0", PORT_NUM);
    if (server.get_fd() == -1) {
        SST_print_error_exit("Failed to open server socket on port %d",
                             PORT_NUM);
    }

    std::printf("Secure IPFS Server listening on port %d...\n", PORT_NUM);

    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    int clnt_sock =
        accept(server.get_fd(), reinterpret_cast<struct sockaddr*>(&clnt_addr),
               &clnt_addr_size);
    if (clnt_sock == -1) {
        SST_print_error_exit("accept() error");
    }

    std::printf("Client connected\n");

    SST_ctx_t* ctx = init_SST(argv[1]);
    if (ctx == nullptr) {
        SST_print_error_exit("init_SST() failed.");
    }

    session_key_list_t* s_key_list = init_empty_session_key_list();
    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == nullptr) {
        SST_print_error_exit("Failed server_secure_comm_setup().");
    }

    pthread_t thread;
    pthread_create(&thread, nullptr, &receive_thread,
                   static_cast<void*>(session_ctx));

    sleep(2);
    pthread_cancel(thread);
    pthread_join(thread, nullptr);

    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    close(clnt_sock);
    free_SST_ctx_t(ctx);

    std::printf("Server finished\n");
    return 0;
}
