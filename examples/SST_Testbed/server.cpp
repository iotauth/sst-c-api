#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>   // errno, EPIPE
#include <csignal>  // sig_atomic_t
#include <cstdlib>  // free, EXIT_FAILURE
#include <cstring>  // memset
extern "C" {
#include "../../c_api.h"
}

volatile int active_clients = 0;
volatile sig_atomic_t stop_server = 0;
pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
const int UDP_IDLE_TIMEOUT_SEC = 10;

// Struct for arguments for each thread
struct ThreadArgs {
    int client_sock;
    SST_ctx_t* ctx;
    bool udp_close_socket;
};

// For pthread_create()
void* receive_and_print_messages(void* thread_args) {
    ThreadArgs* args = static_cast<ThreadArgs*>(thread_args);
    int clnt_sock = args->client_sock;
    SST_ctx_t* ctx = args->ctx;
    bool udp_close_socket = args->udp_close_socket;
    session_key_list_t* s_key_list = init_empty_session_key_list();
    delete args;  // no longer needed

    SST_session_ctx_t* session_ctx =
        server_secure_comm_setup(ctx, clnt_sock, s_key_list);
    if (session_ctx == NULL) {
        SST_print_error("There is no session key.");
        if (udp_close_socket && close(clnt_sock) < 0) {
            SST_print_error("close() error");
        }
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
    char hello[] = "Hello";
    int count = 0;
    for (;;) {
        if (!udp_close_socket) { // TCP sets this bool to true, so this block is only for UDP
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(clnt_sock, &rfds);

            struct timeval tv;
            tv.tv_sec = UDP_IDLE_TIMEOUT_SEC;
            tv.tv_usec = 0;

            int ready = select(clnt_sock + 1, &rfds, NULL, NULL, &tv);
            if (ready < 0) { // Error occurred
                if (errno == EINTR) {
                    continue;
                }
                SST_print_error("select() error in UDP thread");
                break;
            }
            if (ready == 0) { // Timeout occurred, meaning no messages received for UDP_IDLE_TIMEOUT_SEC seconds
                SST_print_log("UDP idle timeout reached (%d seconds). Stopping server.",
                              UDP_IDLE_TIMEOUT_SEC);
                break;
            } // else ready > 0 means there is a message to read, so continue to read_secure_message below
        }

        int ret = read_secure_message(received_buf, session_ctx);
        if (ret < 0) {
            SST_print_error("Failed to read secure message.");
            break;
        } else if (ret == 0) {
            SST_print_error("Connection closed");
            break;
        }
        // Process the received_buf message
        SST_print_log("Received message %d from socket: %d: %.*s", count,
                      clnt_sock, ret,
                      reinterpret_cast<const char*>(received_buf));
        count++;
        int msg = send_secure_message(hello, strlen(hello), session_ctx);
        if (msg < 0) {
            if (errno == EPIPE) {
                SST_print_error(
                    "Failed send_secure_message(): client disconnected "
                    "(EPIPE).");
            } else {
                SST_print_error("Failed send_secure_message().");
            }
            break;
        }
    }

    SST_print_log("Client %d disconnected.", clnt_sock);
    if (udp_close_socket && close(clnt_sock) < 0) {
        SST_print_error("close() error");
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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        SST_print_error("Usage: %s <config_path>", argv[0]);
        return EXIT_FAILURE;
    }

    // Do not terminate process on write() to a disconnected socket.
    signal(SIGPIPE, SIG_IGN);

    SST_ctx_t* ctx = init_SST(argv[1]);
    if (ctx == NULL) {
        SST_print_error("Failed init_SST().");
        return EXIT_FAILURE;
    }

    bool use_tcp = std::strcmp((const char*)ctx->config.network_protocol, "TCP") == 0;
    int sock_type = use_tcp ? SOCK_STREAM : SOCK_DGRAM;
    int port_num = ctx->config.entity_server_port_num;
    if (port_num <= 0 || port_num > 65535) {
        SST_print_error("Invalid entity.server.port.number in config: %d",
                        port_num);
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }

    // Initialize the socket
    int serv_sock;

    struct sockaddr_in serv_addr;
    serv_sock = socket(PF_INET, sock_type, 0);
    if (serv_sock < 0) {
        SST_print_error("socket() error");
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }

    int on = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        SST_print_error("socket option set error");
        close(serv_sock);
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port_num);

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        SST_print_error("bind() error");
        close(serv_sock);
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }

    if (use_tcp) {
        if (listen(serv_sock, 5) < 0) {
            SST_print_error("listen() error");
            close(serv_sock);
            free_SST_ctx_t(ctx);
            return EXIT_FAILURE;
        }

        // Accept incoming client connections
        // Run until all clients are done
        while (!stop_server) {
            // rfds watches the sockets and tells when a descriptor is ready
            // (ready means the listening socket has an incoming connection)
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(serv_sock, &rfds);

            // Using a timeout allows periodically checking
            // stop_server instead of blocking forever in accept()
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;  // 100 ms timeout

            // ready will be > 0 if there is an incoming connection
            int ready = select(serv_sock + 1, &rfds, NULL, NULL, &tv);
            if (ready < 0) {
                if (errno == EINTR) continue;  // Interrupted by signal; retry
                SST_print_error("select() error");
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
                accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
            if (clnt_sock < 0) {
                SST_print_error("accept() error");
                continue;
            }
            SST_print_log("New client: socket %d", clnt_sock);

            // Update the number of active clients
            // Use a mutex to protect the counter
            pthread_mutex_lock(&count_mutex);
            active_clients++;
            pthread_mutex_unlock(&count_mutex);

            ThreadArgs* args = new ThreadArgs;
            args->client_sock = clnt_sock;
            args->ctx = ctx;
            args->udp_close_socket = true;

            pthread_t t;
            int err = pthread_create(&t, NULL, receive_and_print_messages, args);
            if (err != 0) {
                SST_print_error("pthread_create() error");

                // Thread creation failed, so decrement active_clients
                pthread_mutex_lock(&count_mutex);
                active_clients--;
                if (active_clients == 0) {
                    stop_server =
                        1;  // If this was the last client, tell main to stop
                }
                pthread_mutex_unlock(&count_mutex);

                if (close(clnt_sock) < 0) {
                    SST_print_error("close() error");
                    close(serv_sock);
                    free_SST_ctx_t(ctx);
                    delete args;
                    return EXIT_FAILURE;
                }

                delete args;
                continue;
            }
            pthread_detach(t);
        }
    } else {
        // UDP server: use the datagram socket directly.
        pthread_mutex_lock(&count_mutex);
        active_clients = 1;
        pthread_mutex_unlock(&count_mutex);

        ThreadArgs* args = new ThreadArgs;
        args->client_sock = serv_sock;
        args->ctx = ctx;
        args->udp_close_socket = false;

        pthread_t t;
        int err = pthread_create(&t, NULL, receive_and_print_messages, args);
        if (err != 0) {
            SST_print_error("pthread_create() error");
            if (close(serv_sock) < 0) {
                SST_print_error("close() error");
            }
            delete args;
            free_SST_ctx_t(ctx);
            return EXIT_FAILURE;
        }
        pthread_detach(t);

        // Wait until the UDP connection exits and signals stop_server.
        while (!stop_server) {
            usleep(100000);
        }
    }

    SST_print_log("Successfully finished communication.");

    if (close(serv_sock) < 0) {
        SST_print_error("close() error");
        return EXIT_FAILURE;
    }

    free_SST_ctx_t(ctx);
}
