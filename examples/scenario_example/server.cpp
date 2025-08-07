#include <sys/socket.h>
#include <unistd.h>

#include <fstream>
#include <iostream>

extern "C" {
#include "../../c_api.h"
}

// Struct for arguments for each thread
struct ThreadArgs {
    int client_sock;
    char *config_path;
};

// For pthread_create()
void* receive_and_print_messages(void* thread_args) {
    ThreadArgs* args = static_cast<ThreadArgs*>(thread_args);
    int clnt_sock = args->client_sock;
    char* config_path = args->config_path;
    delete args;  // no longer needed

    SST_ctx_t *ctx = init_SST(config_path);
    session_key_list_t *s_key_list = init_empty_session_key_list();
    SST_session_ctx_t *session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        std::cerr << "There is no session key.\n" << std::endl;
        close(clnt_sock);
        free_SST_ctx_t(ctx);
        free_session_key_list_t(s_key_list);
        return NULL;
    }

    unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
    // Receive messages from client
    for (;;) {
        int ret =
            read_secure_message(received_buf, session_ctx);
        if (ret == -1) {
            std::cerr << "Failed to read secure message." << std::endl;
            break;
        } else if (ret == 0) {
            std::cerr << "Connection closed" << std::endl;
            break;
        }
        // Process the received_buf message
        std::cout.write(reinterpret_cast<const char *>(received_buf), ret);
        std::cout << std::endl; // if you want a newline
    }

    std::cout << "Client " << clnt_sock << " disconnected.\n";
    if (close(clnt_sock) == -1) {
        std::cerr << "close() error" << std::endl;
        return NULL;
    }
    free(session_ctx);
    free_SST_ctx_t(ctx);
    free_session_key_list_t(s_key_list);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_path>" << std::endl;
        return EXIT_FAILURE;
    }

    // Initialize the sockets
    int serv_sock;
    const int PORT_NUM = 21100;

    struct sockaddr_in serv_addr;
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
    serv_addr.sin_port = htons(PORT_NUM);

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
        -1) {
        std::cerr << "bind() error" << std::endl;
        return EXIT_FAILURE;
    }

    if (listen(serv_sock, 5) == -1) {
        std::cerr << "listen() error" << std::endl;
        return EXIT_FAILURE;
    }

    // Accept incoming client connections
    while (true) {
        struct sockaddr_in clnt_addr;
        socklen_t clnt_addr_size = sizeof(clnt_addr);
        int clnt_sock =
            accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1) {
            std::cerr << "accept() error" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << "New client: socket " << clnt_sock << std::endl;

        ThreadArgs* args = new ThreadArgs;
        args->client_sock = clnt_sock;
        args->config_path = argv[1];

        pthread_t t;
        if (pthread_create(&t, NULL, receive_and_print_messages, args) != 0) {
            std::cerr << "pthread_create() error" << std::endl;

            if (close(clnt_sock) == -1) {
                std::cerr << "close() error" << std::endl;
                return EXIT_FAILURE;
            }

            delete args;
            continue;
        }
        pthread_detach(t);
    }

    std::cout << "Finished communication." << std::endl;

    if (close(serv_sock) == -1) {
        std::cerr << "close() error" << std::endl;
        return EXIT_FAILURE;
    }
}
