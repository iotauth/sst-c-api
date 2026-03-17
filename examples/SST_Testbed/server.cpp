#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>   // errno, EPIPE
#include <csignal>  // sig_atomic_t
#include <cstdlib>  // free, EXIT_FAILURE
#include <cstring>  // memset
#include <vector>
extern "C" {
#include "../../c_api.h"
}

volatile int active_clients = 0;
volatile sig_atomic_t stop_server = 0;
pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
const int UDP_IDLE_TIMEOUT_SEC = 10;
const int UDP_WORKER_COUNT = 512;

// Returns the number of UDP worker threads to start
// based on the SST_UDP_WORKERS environment variable (default: UDP_WORKER_COUNT).
// This is because UDP does not have an accept() loop to handle multiple clients
// so we need a pool of worker threads each with their own socket to handle concurrent clients.
static int get_udp_worker_count() {
    const char* env = std::getenv("SST_UDP_WORKERS");
    if (env == NULL || env[0] == '\0') {
        return UDP_WORKER_COUNT;
    }

    char* endptr = NULL;
    long parsed = std::strtol(env, &endptr, 10);
    if (endptr == env || *endptr != '\0' || parsed < 1) {
        errno = 0;
        SST_print_error("Invalid SST_UDP_WORKERS='%s'. Using default %d.", env,
                        UDP_WORKER_COUNT);
        return UDP_WORKER_COUNT;
    }

    if (parsed > UDP_WORKER_COUNT) {
        return UDP_WORKER_COUNT;
    }
    return static_cast<int>(parsed);
}

// Struct for arguments for each thread
struct ThreadArgs {
    int client_sock;
    SST_ctx_t* ctx;
    bool use_udp;
    bool close_socket;
};

// For pthread_create()
void* receive_and_print_messages(void* thread_args) {
    ThreadArgs* args = static_cast<ThreadArgs*>(thread_args);
    int clnt_sock = args->client_sock;
    SST_ctx_t* ctx = args->ctx;
    bool use_udp = args->use_udp;
    bool close_socket = args->close_socket;
    delete args;  // no longer needed

    bool udp_idle_timeout = false;

    while (true) {
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
                    continue;
                }
                SST_print_error("select() error in UDP thread");
                break;
            }
            if (ready == 0) {
                udp_idle_timeout = true;
                break;
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
                continue;
            }
            break;
        }

        unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
        char hello[] = "Hello";
        int count = 0;
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
    }

    if (udp_idle_timeout) {
        SST_print_log("UDP worker on socket %d idle for %d seconds, exiting.",
                      clnt_sock, UDP_IDLE_TIMEOUT_SEC);
    }

    if (close_socket && close(clnt_sock) < 0) {
        SST_print_error("close() error");
    }

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
            args->use_udp = false;
            args->close_socket = true;

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
        // UDP server: create a worker pool.
        // Each worker has its own UDP socket bound to the same port with
        // SO_REUSEPORT, allowing concurrent sessions without changing session_ctx.
        int worker_count = get_udp_worker_count();
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
            int udp_sock = socket(PF_INET, SOCK_DGRAM, 0);
            if (udp_sock < 0) {
                SST_print_error("UDP worker socket() error");
                continue;
            }

            int worker_on = 1;
            if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &worker_on,
                           sizeof(worker_on)) < 0) {
                SST_print_error("UDP worker SO_REUSEADDR error");
                close(udp_sock);
                continue;
            }
#ifdef SO_REUSEPORT
            if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEPORT, &worker_on,
                           sizeof(worker_on)) < 0) {
                SST_print_error("UDP worker SO_REUSEPORT error");
                close(udp_sock);
                continue;
            }
#else
            SST_print_error("SO_REUSEPORT not available; cannot run concurrent UDP workers.");
            close(udp_sock);
            break;
#endif

            if (bind(udp_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) <
                0) {
                SST_print_error("UDP worker bind() error");
                close(udp_sock);
                continue;
            }

            // Prevent workers from blocking forever inside UDP handshake reads.
            struct timeval rcv_to;
            rcv_to.tv_sec = UDP_IDLE_TIMEOUT_SEC;
            rcv_to.tv_usec = 0;
            if (setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_to,
                           sizeof(rcv_to)) < 0) {
                SST_print_error("UDP worker SO_RCVTIMEO error");
                close(udp_sock);
                continue;
            }

            ThreadArgs* args = new ThreadArgs;
            args->client_sock = udp_sock;
            args->ctx = ctx;
            args->use_udp = true;
            args->close_socket = true;

            pthread_t t;
            int err = pthread_create(&t, NULL, receive_and_print_messages, args);
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
