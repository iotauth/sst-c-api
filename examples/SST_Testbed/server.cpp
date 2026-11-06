#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>   // errno, EPIPE
#include <csignal>  // sig_atomic_t
#include <cstdio>   // fflush, stdout
#include <cstdlib>  // free, EXIT_FAILURE
#include <cstring>  // memset
#include <vector>
extern "C" {
#include "../../src/c_api.h"
}

int active_clients = 0;  // All accesses are protected by count_mutex.
volatile sig_atomic_t stop_server = 0;
pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
const int UDP_IDLE_TIMEOUT_SEC = 10;
const int UDP_DEFAULT_WORKER_COUNT = 16;
const int UDP_MAX_WORKER_COUNT = 105;

static void handle_shutdown_signal(int) { stop_server = 1; }

static bool parse_udp_worker_count(const char* value, int* worker_count) {
    char* endptr = NULL;
    errno = 0;
    long parsed = std::strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '\0' || parsed < 1 ||
        parsed > UDP_MAX_WORKER_COUNT) {
        return false;
    }
    *worker_count = static_cast<int>(parsed);
    return true;
}

// Struct for arguments for each thread
struct ThreadArgs {
    int client_sock;
    SST_ctx_t* ctx;
    bool use_udp;
    bool close_socket;
};

static int make_udp_worker_socket(int port) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        close(sock);
        return -1;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
        close(sock);
        return -1;
    }
#else
    SST_print_error("SO_REUSEPORT is required for UDP workers.");
    close(sock);
    return -1;
#endif
    struct sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    struct timeval timeout = {};
    timeout.tv_sec = UDP_IDLE_TIMEOUT_SEC;
    if (bind(sock, reinterpret_cast<struct sockaddr*>(&address),
             sizeof(address)) < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
            0) {
        close(sock);
        return -1;
    }
    return sock;
}

static bool release_udp_peer(int& sock, int port) {
    // The C API connects the worker to one sender. Replace it with a fresh
    // listener to clear that peer filter on both Linux and BSD/macOS.
    int listener = make_udp_worker_socket(port);
    if (listener < 0) {
        SST_print_error("Failed to reset UDP worker: %s", strerror(errno));
        return false;
    }
    close(sock);
    sock = listener;
    return true;
}

// For pthread_create()
void* receive_and_print_messages(void* thread_args) {
    ThreadArgs* args = static_cast<ThreadArgs*>(thread_args);
    int clnt_sock = args->client_sock;
    SST_ctx_t* ctx = args->ctx;
    bool use_udp = args->use_udp;
    bool close_socket = args->close_socket;
    delete args;  // no longer needed

    while (true) {
        if (stop_server) {
            break;
        }
        if (use_udp) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(clnt_sock, &rfds);

            struct timeval tv;
            tv.tv_sec = UDP_IDLE_TIMEOUT_SEC;
            tv.tv_usec = 0;

            int ready = select(clnt_sock + 1, &rfds, NULL, NULL, &tv);
            if (ready < 0) {
                if (errno == EINTR) {
                    if (stop_server) {
                        break;
                    }
                    continue;
                }
                SST_print_error("select() error in UDP thread");
                break;
            }
            if (ready == 0) {
                continue;
            }
        }

        session_key_list_t* s_key_list = init_empty_session_key_list();
        SST_session_ctx_t* session_ctx =
            server_secure_comm_setup(ctx, clnt_sock, s_key_list);
        if (session_ctx == NULL) {
            errno = 0;
            SST_print_error("There is no session key.");
            free_session_key_list_t(s_key_list);
            if (use_udp) {
                // Keep serving other UDP clients on this worker.
                if (!release_udp_peer(clnt_sock,
                                      ctx->config.entity_server_port_num))
                    break;
                continue;
            }
            break;
        }

        unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
        char hello[] = "Hello";
        int count = 1;
        for (;;) {
            int ret = read_secure_message(received_buf, session_ctx);
            if (ret < 0) {
                SST_print_error("Failed to read secure message.");
                break;
            } else if (ret == 0) {
                SST_print_error("Connection closed");
                break;
            }

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
        free(session_ctx);
        free_session_key_list_t(s_key_list);

        if (!use_udp) {
            break;
        }
        if (!release_udp_peer(clnt_sock, ctx->config.entity_server_port_num))
            break;
    }

    if (close_socket && close(clnt_sock) < 0) {
        SST_print_error("close() error");
    }

    // Once the thread has finished, decrement the number of active clients
    // Use a mutex to protect the counter
    pthread_mutex_lock(&count_mutex);
    --active_clients;
    if (!use_udp && active_clients == 0)
        stop_server = 1;  // If this was the last client, tell main to stop
    pthread_mutex_unlock(&count_mutex);

    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 4) {
        SST_print_error("Usage: %s <config_path> [--workers 1-%d]", argv[0],
                        UDP_MAX_WORKER_COUNT);
        return EXIT_FAILURE;
    }

    int udp_worker_count = UDP_DEFAULT_WORKER_COUNT;
    bool workers_requested = false;
    if (argc == 4) {
        if (std::strcmp(argv[2], "--workers") != 0 ||
            !parse_udp_worker_count(argv[3], &udp_worker_count)) {
            SST_print_error("Usage: %s <config_path> [--workers 1-%d]", argv[0],
                            UDP_MAX_WORKER_COUNT);
            return EXIT_FAILURE;
        }
        workers_requested = true;
    }

    // Do not terminate process on write() to a disconnected socket.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_shutdown_signal);

    SST_ctx_t* ctx = init_SST(argv[1]);
    if (ctx == NULL) {
        SST_print_error("Failed init_SST().");
        return EXIT_FAILURE;
    }

    bool use_tcp =
        std::strcmp((const char*)ctx->config.network_protocol, "TCP") == 0;

    if (use_tcp && workers_requested) {
        SST_print_error("--workers is only valid with a UDP server config.");
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }
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
            int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr,
                                   &clnt_addr_size);
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
            args->use_udp = false;
            args->close_socket = true;

            pthread_t t;
            int err =
                pthread_create(&t, NULL, receive_and_print_messages, args);
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
        // UDP server: create a worker pool.
        // Each worker has its own UDP socket bound to the same port with
        // SO_REUSEPORT, allowing concurrent sessions without changing
        // session_ctx.
        int worker_count = udp_worker_count;
        if (close(serv_sock) < 0) {
            SST_print_error("close() error");
            free_SST_ctx_t(ctx);
            return EXIT_FAILURE;
        }
        serv_sock = -1;

        std::vector<pthread_t> workers;
        workers.reserve(worker_count);

        pthread_mutex_lock(&count_mutex);
        active_clients = 0;
        stop_server = 0;
        pthread_mutex_unlock(&count_mutex);

        for (int i = 0; i < worker_count; ++i) {
            int udp_sock = make_udp_worker_socket(port_num);
            if (udp_sock < 0) {
                SST_print_error("Failed to create UDP worker: %s",
                                strerror(errno));
                continue;
            }

            ThreadArgs* args = new ThreadArgs;
            args->client_sock = udp_sock;
            args->ctx = ctx;
            args->use_udp = true;
            args->close_socket = true;

            pthread_t t;
            int err =
                pthread_create(&t, NULL, receive_and_print_messages, args);
            if (err != 0) {
                SST_print_error("pthread_create() error");
                close(udp_sock);
                delete args;
                continue;
            }

            pthread_mutex_lock(&count_mutex);
            active_clients++;
            pthread_mutex_unlock(&count_mutex);

            workers.push_back(t);
        }

        if (workers.empty()) {
            SST_print_error("No UDP workers started.");
            free_SST_ctx_t(ctx);
            return EXIT_FAILURE;
        }

        SST_print_log("UDP server ready on port %d (%zu workers).", port_num,
                      workers.size());
        std::fflush(stdout);

        for (size_t i = 0; i < workers.size(); ++i) {
            pthread_join(workers[i], NULL);
        }
    }

    SST_print_log("Successfully finished communication.");

    if (serv_sock >= 0 && close(serv_sock) < 0) {
        SST_print_error("close() error");
        return EXIT_FAILURE;
    }

    free_SST_ctx_t(ctx);
}
