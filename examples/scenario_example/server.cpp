#include <sys/socket.h>
#include <unistd.h>

#include <csignal>  // sig_atomic_t
#include <cstring>  // memset
#include <fstream>
#include <iostream>

extern "C" {
#include "../../c_api.h"
}

volatile int active_clients = 0;
volatile sig_atomic_t stop_server = 0;
pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;

// Struct for arguments for each thread
struct ThreadArgs {
    int client_sock;
    SST_ctx_t *ctx;
};

// For pthread_create()
void *receive_and_print_messages(void *thread_args) {
    ThreadArgs *args = static_cast<ThreadArgs *>(thread_args);
    int clnt_sock = args->client_sock;
    SST_ctx_t *ctx = args->ctx;
    session_key_list_t *s_key_list = init_empty_session_key_list();
    delete args;  // no longer needed

    SST_session_ctx_t *session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        std::cerr << "There is no session key.\n" << std::endl;
        close(clnt_sock);
        free_session_key_list_t(s_key_list);

        // Decrement active client count on failure path
        pthread_mutex_lock(&count_mutex);
        active_clients--;
        // If this was the last (or only) client, tell main to stop
        if (active_clients == 0) stop_server = 1;
        pthread_mutex_unlock(&count_mutex);

        return NULL;
    }

    unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
    // Receive messages from client
    for (;;) {
        int ret = read_secure_message(received_buf, session_ctx);
        if (ret < 0) {
            std::cerr << "Failed to read secure message." << std::endl;
            break;
        } else if (ret == 0) {
            std::cerr << "Connection closed" << std::endl;
            break;
        }
        // Process the received_buf message
        std::cout << "Received message from socket: " << clnt_sock << ": ";
        std::cout.write(reinterpret_cast<const char *>(received_buf), ret);
        std::cout << std::endl;
    }

    std::cout << "Client " << clnt_sock << " disconnected.\n";
    if (close(clnt_sock) < 0) {
        std::cerr << "close() error" << std::endl;
        return NULL;
    }
    free(session_ctx);

    // Once the thread has finished, decrement the number of active clients
    // Use a mutex to protect the counter
    pthread_mutex_lock(&count_mutex);
    --active_clients;
    if (active_clients == 0)
        stop_server = 1;  // If this was the last client, tell main to stop
    pthread_mutex_unlock(&count_mutex);

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
    if (serv_sock < 0) {
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

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "bind() error" << std::endl;
        return EXIT_FAILURE;
    }

    if (listen(serv_sock, 5) < 0) {
        std::cerr << "listen() error" << std::endl;
        return EXIT_FAILURE;
    }

    SST_ctx_t *ctx = init_SST(argv[1]);
    session_key_list_t *s_key_list = init_empty_session_key_list();

    // Accept incoming client connections
    // Run until all clients are done
    while (!stop_server) {
        // rfds with select() watches the sets/sockets and tells when a
        // descriptor is ready (ready means the listening socket has an incoming
        // connection)
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(serv_sock, &rfds);

        // Using a timeout with select() allows us to periodically check
        // stop_server instead of blocking forever in accept()
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100 ms timeout

        // ready will be > 0 if there is an incoming connection
        int ready = select(serv_sock + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;  // Interrupted by signal; retry
            std::cerr << "select() error" << std::endl;
            continue;
        }
        if (stop_server) {
            break;  // all clients are done; exit loop
        }

        if (ready == 0) {
            // timeout: no incoming connection; loop to re-check stop_server
            continue;
        }

        struct sockaddr_in clnt_addr;
        socklen_t clnt_addr_size = sizeof(clnt_addr);
        int clnt_sock =
            accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
        if (clnt_sock < 0) {
            std::cerr << "accept() error" << std::endl;
            continue;
        }
        std::cout << "New client: socket " << clnt_sock << std::endl;

        // Update the number of active clients
        // Use a mutex to protect the counter
        pthread_mutex_lock(&count_mutex);
        active_clients++;
        pthread_mutex_unlock(&count_mutex);

        ThreadArgs *args = new ThreadArgs;
        args->client_sock = clnt_sock;
        args->ctx = ctx;

        pthread_t t;
        if (pthread_create(&t, NULL, receive_and_print_messages, args) != 0) {
            std::cerr << "pthread_create() error" << std::endl;

            // Thread creation failed, so decrement active_clients
            pthread_mutex_lock(&count_mutex);
            active_clients--;
            if (active_clients == 0) {
                stop_server =
                    1;  // If this was the last client, tell main to stop
            }
            pthread_mutex_unlock(&count_mutex);

            if (close(clnt_sock) < 0) {
                std::cerr << "close() error" << std::endl;
                return EXIT_FAILURE;
            }

            delete args;
            continue;
        }
        pthread_detach(t);
    }

    std::cout << "Successfully finished communication." << std::endl;

    if (close(serv_sock) < 0) {
        std::cerr << "close() error" << std::endl;
        return EXIT_FAILURE;
    }

    free_SST_ctx_t(ctx);
    free_session_key_list_t(s_key_list);
}
