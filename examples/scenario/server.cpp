#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <unistd.h>

#include "../../c_api.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./" << argv[0] << " <config_path>" << std::endl;
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
    pthread_t thread;
    pthread_create(&thread, NULL, &receive_thread_read_one_each, (void *)session_ctx);
    unsigned char *decrypted;
    read_secure_message(session_ctx->sock, &decrypted, session_ctx);

    std::cout << "Received message: " << reinterpret_cast<const char*>(decrypted) << std::endl;

    if (close(clnt_sock) == -1) {
        std::cerr << "close" << std::endl;
        return EXIT_FAILURE;
    }

    close(clnt_sock);
    // pthread_cancel(thread);
    printf("Finished communication\n");
    free_SST_ctx_t(ctx);
}