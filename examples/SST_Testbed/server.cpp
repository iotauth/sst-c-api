#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <bit>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

extern "C" {
#include "../../src/c_api.h"
}

volatile sig_atomic_t stop_server = 0;
const int UDP_IDLE_TIMEOUT_SEC = 10;
const int UDP_DEFAULT_WORKER_COUNT = 16;
const int UDP_MAX_WORKER_COUNT = 105;

static void handle_shutdown_signal(int) { stop_server = 1; }

struct ServerState {
    explicit ServerState(SST_ctx_t* context) : ctx(context, &free_SST_ctx_t) {}
    std::unique_ptr<SST_ctx_t, decltype(&free_SST_ctx_t)> ctx;
    std::mutex mutex;
    int active_clients = 0;
    std::atomic<bool> finished = false;
};

static void finish_worker(ServerState& state, bool use_udp) {
    std::scoped_lock lock(state.mutex);
    --state.active_clients;
    if (!use_udp && state.active_clients == 0) state.finished = true;
}

static bool parse_udp_worker_count(const char* value, int* worker_count) {
    char* endptr = nullptr;
    errno = 0;
    long parsed = std::strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '\0' || parsed < 1 ||
        parsed > UDP_MAX_WORKER_COUNT)
        return false;
    *worker_count = static_cast<int>(parsed);
    return true;
}

static int bind_ipv4(int sock, int port) {
    sockaddr_in ipv4{};
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
    ipv4.sin_port = htons(port);
    // POSIX IPv4 socket addresses have the same size as sockaddr. Copying the
    // representation avoids accessing a sockaddr_in through an unrelated type.
    auto address = std::bit_cast<sockaddr>(ipv4);
    return bind(sock, &address, sizeof(address));
}

static bool configure_udp_worker(int sock) {
#ifdef SO_REUSEPORT
    if (int on = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
        return false;
#else
    SST_print_error("SO_REUSEPORT is required for UDP workers.");
    return false;
#endif
    timeval timeout{};
    timeout.tv_sec = UDP_IDLE_TIMEOUT_SEC;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0;
}

static int make_listener(int port, bool use_udp) {
    int sock = socket(AF_INET, use_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sock < 0) return -1;
    if (int on = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 ||
        (use_udp && !configure_udp_worker(sock)) || bind_ipv4(sock, port) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static bool release_udp_peer(int& sock, int port) {
    // The C API connects the worker to one sender. A fresh listener clears
    // that peer filter on both Linux and BSD/macOS.
    int listener = make_listener(port, true);
    if (listener < 0) {
        SST_print_error("Failed to reset UDP worker: %s", strerror(errno));
        return false;
    }
    close(sock);
    sock = listener;
    return true;
}

static int poll_socket(int sock, int timeout_ms) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(sock, &readable);
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    int ready = select(sock + 1, &readable, nullptr, nullptr, &timeout);
    if (ready < 0 && errno == EINTR) return 0;
    if (ready < 0) SST_print_error("select() error");
    return ready;
}

static bool wait_for_udp_peer(int sock) {
    while (!stop_server) {
        int ready = poll_socket(sock, UDP_IDLE_TIMEOUT_SEC * 1000);
        if (ready < 0) return false;
        if (ready > 0) return true;
    }
    return false;
}

static void exchange_messages(SST_session_ctx_t* session) {
    std::array<unsigned char, MAX_SECURE_COMM_MSG_LENGTH> received{};
    std::string reply = "Hello";
    int count = 1;
    for (;;) {
        int length = read_secure_message(received.data(), session);
        if (length <= 0) {
            SST_print_error(length < 0 ? "Failed to read secure message."
                                       : "Connection closed");
            return;
        }
        std::string message(received.begin(), received.begin() + length);
        SST_print_log("Received message %d from socket: %d: %.*s", count++,
                      session->sock, length, message.c_str());
        if (send_secure_message(reply.data(), reply.size(), session) < 0) {
            SST_print_error(errno == EPIPE ? "Failed send_secure_message(): "
                                             "client disconnected (EPIPE)."
                                           : "Failed send_secure_message().");
            return;
        }
    }
}

static void serve_session(SST_ctx_t* ctx, int sock) {
    auto keys =
        std::unique_ptr<session_key_list_t, decltype(&free_session_key_list_t)>(
            init_empty_session_key_list(), &free_session_key_list_t);
    if (!keys) {
        SST_print_error("Failed to allocate session key list.");
        return;
    }
    auto session =
        std::unique_ptr<SST_session_ctx_t, decltype(&free_session_ctx)>(
            server_secure_comm_setup(ctx, sock, keys.get()), &free_session_ctx);
    if (!session) {
        errno = 0;
        SST_print_error("There is no session key.");
        return;
    }
    exchange_messages(session.get());
    SST_print_log("Client %d disconnected.", sock);
}

static void serve_worker(const std::shared_ptr<ServerState>& state, int sock,
                         bool use_udp) {
    do {
        if (stop_server || (use_udp && !wait_for_udp_peer(sock))) break;
        serve_session(state->ctx.get(), sock);
    } while (use_udp && !stop_server &&
             release_udp_peer(sock, state->ctx->config.entity_server_port_num));
    if (close(sock) < 0) SST_print_error("close() error");
    finish_worker(*state, use_udp);
}

static std::optional<std::jthread> start_worker(
    const std::shared_ptr<ServerState>& state, int sock, bool use_udp) {
    {
        std::scoped_lock lock(state->mutex);
        ++state->active_clients;
    }
    try {
        // std::jthread owns a copy of state, keeping the C context alive until
        // the worker finishes, including detached TCP workers during shutdown.
        return std::jthread(&serve_worker, state, sock, use_udp);
    } catch (const std::system_error& error) {
        SST_print_error("Failed to start worker: %s", error.what());
        close(sock);
        finish_worker(*state, use_udp);
        return std::nullopt;
    }
}

static int run_tcp_server(const std::shared_ptr<ServerState>& state, int port) {
    int listener = make_listener(port, false);
    if (listener < 0) {
        SST_print_error("Failed to create TCP listener.");
        return EXIT_FAILURE;
    }
    if (listen(listener, 5) < 0) {
        SST_print_error("listen() error");
        close(listener);
        return EXIT_FAILURE;
    }
    while (!stop_server && !state->finished) {
        int ready = poll_socket(listener, 100);
        if (stop_server || state->finished) break;
        if (ready <= 0) continue;
        int client = accept(listener, nullptr, nullptr);
        if (client < 0) {
            SST_print_error("accept() error");
            continue;
        }
        SST_print_log("New client: socket %d", client);
        if (auto worker = start_worker(state, client, false)) worker->detach();
    }
    return close(listener) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int run_udp_server(const std::shared_ptr<ServerState>& state, int port,
                          int worker_count) {
    std::vector<std::jthread> workers;
    workers.reserve(worker_count);
    for (int i = 0; i < worker_count; ++i) {
        int sock = make_listener(port, true);
        if (sock < 0) {
            SST_print_error("Failed to create UDP worker: %s", strerror(errno));
            continue;
        }
        if (auto worker = start_worker(state, sock, true))
            workers.push_back(std::move(*worker));
    }
    if (workers.empty()) {
        SST_print_error("No UDP workers started.");
        return EXIT_FAILURE;
    }
    SST_print_log("UDP server ready on port %d (%zu workers).", port,
                  workers.size());
    std::fflush(stdout);
    for (auto& worker : workers) worker.join();
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 4) {
        SST_print_error("Usage: %s <config_path> [--workers 1-%d]", argv[0],
                        UDP_MAX_WORKER_COUNT);
        return EXIT_FAILURE;
    }
    int worker_count = UDP_DEFAULT_WORKER_COUNT;
    bool workers_requested = argc == 4;
    if (workers_requested &&
        (std::strcmp(argv[2], "--workers") != 0 ||
         !parse_udp_worker_count(argv[3], &worker_count))) {
        SST_print_error("Usage: %s <config_path> [--workers 1-%d]", argv[0],
                        UDP_MAX_WORKER_COUNT);
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_shutdown_signal);
    auto state = std::make_shared<ServerState>(init_SST(argv[1]));
    if (!state->ctx) {
        SST_print_error("Failed init_SST().");
        return EXIT_FAILURE;
    }
    bool use_tcp = std::strcmp(state->ctx->config.network_protocol, "TCP") == 0;
    if (use_tcp && workers_requested) {
        SST_print_error("--workers is only valid with a UDP server config.");
        return EXIT_FAILURE;
    }
    int port = state->ctx->config.entity_server_port_num;
    if (port < 1 || port > 65535) {
        SST_print_error("Invalid entity.server.port.number in config: %d",
                        port);
        return EXIT_FAILURE;
    }
    int result = use_tcp ? run_tcp_server(state, port)
                         : run_udp_server(state, port, worker_count);
    if (result == EXIT_SUCCESS)
        SST_print_log("Successfully finished communication.");
    return result;
}
