// Compilation: g++ -g -O0 -o server server.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -L/usr/local/lib -lsst-c-api -lssl -lcrypto -pthread
// Execution: ./server <config_path>

#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
    #include <c/c_api.h>
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_path>" << std::endl;
        return EXIT_FAILURE;
    }

    // Initialize the sockets
    int serv_sock, clnt_sock;
    const char *PORT_NUM = "21100";

    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        std::cerr << "socket() error" << std::endl;
        return EXIT_FAILURE;
    }

    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        std::cerr << "socket option set error\n" << std::endl;
        return EXIT_FAILURE;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(PORT_NUM));

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        std::cerr << "bind() error" << std::endl;
        return EXIT_FAILURE;
    }

    if (listen(serv_sock, 5) == -1) {
        std::cerr << "listen() error" << std::endl;
        return EXIT_FAILURE;
    }

    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1) {
        std::cerr << "accept() error" << std::endl;
        return EXIT_FAILURE;
    }

    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);
    session_key_list_t *s_key_list = init_empty_session_key_list();
    SST_session_ctx_t *session_ctx = server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        std::cerr << "There is no session key.\n" << std::endl;
        return EXIT_FAILURE;
    }

    // Receive messages from client
    unsigned char *received_buf;
    unsigned char* received_plaintext;

    for (;;) {
        int ret = read_secure_message(session_ctx->sock, &received_buf, session_ctx);
        if (ret == -1) {
            std::cerr << "Failed to read secure message." << std::endl;
            break;
        } else if (ret == 0) {
            std::cerr << "No more messages to read." << std::endl;
            break;
        }
        // Process the received_buf message
        // TODO: Remove this temporary fix once the C API is fixed.
        // Remove the two 4-byte sequence numbers in the received buffer
        received_plaintext = received_buf + 8;
        std::cout << reinterpret_cast<const char*>(received_plaintext) << std::endl;
    }

    std::cout << "Finished communication." << std::endl;

    if (close(clnt_sock) == -1) {
        std::cerr << "close() error" << std::endl;
        return EXIT_FAILURE;
    }

    free(session_ctx);
    free_SST_ctx_t(ctx);
    free_session_key_list_t(s_key_list);
}
