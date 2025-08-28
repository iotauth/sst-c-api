extern "C" {
#include "../../c_api.h"
// #include "../../ipfs.h"
}

#include <unistd.h>

#include <fstream>
#include <iostream>
#include <thread>

enum AttackType { NONE, REPLAY, DOSK, DOSC, DOSM };

static AttackType parseAttackType(const std::string &s) {
    if (s == "REPLAY" || s == "Replay" || s == "replay") return REPLAY;
    if (s == "DOSK" || s == "DoSK" || s == "DosK" || s == "Dosk" ||
        s == "dosK" || s == "dosk")
        return DOSK;
    if (s == "DOSC" || s == "DoSC" || s == "DosC" || s == "Dosc" ||
        s == "dosC" || s == "dosc")
        return DOSC;
    if (s == "DOSM" || s == "DoSM" || s == "DosM" || s == "Dosc" ||
        s == "dosM" || s == "dosm")
        return DOSM;
    return NONE;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <config_path> <csv_file_path>"
                  << std::endl;
        exit(1);
    }

    // Standard SST initialization
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    if (s_key_list == NULL) {
        std::cerr << "Client failed to get session key.\n" << ::std::endl;
        exit(1);
    }

    // SST Connect to server
    SST_session_ctx_t *session_ctx =
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
        send_secure_message(const_cast<char *>(message.c_str()),
                            message.length(), session_ctx);

        // Parse the attack type
        std::string attack_type_str =
            (comma2 != std::string::npos)
                ? line.substr(
                      comma2 + 1,
                      (comma3 == std::string::npos
                           ? std::string::npos
                           : comma3 - comma2 -
                                 1))  // if there is a 3rd column, grab it
                : "";                 // else, use the empty string

        AttackType attack_type = parseAttackType(attack_type_str);

        // Optional: parameter for the attack type if applicable
        std::string attack_param =
            (comma3 != std::string::npos) ? line.substr(comma3 + 1) : "";

        switch (attack_type) {
            case REPLAY: {
                // Replay Attack
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

                // DOS Attack on get_session_key
                for (int i = 0; i < repeat; ++i) {
                    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
                    if (s_key_list == NULL) {
                        std::cerr << "Client failed to get session key in DOS "
                                     "Key attack.\n"
                                  << ::std::endl;
                        exit(1);
                    }
                }
            } break;

            case DOSC: {
                // Quantity of secure_connect_to_server requests is the fourth
                // column in the CSV
                int repeat = std::stoi(attack_param);
                SST_session_ctx_t *session_ctx[repeat];
                // DOS Attack on secure_connect_to_server
                for (int i = 0; i < repeat; ++i) {
                    s_key_list = get_session_key(ctx, NULL);
                    if (s_key_list == NULL) {
                        std::cerr << "Client failed to get session key in DOS "
                                     "Connect attack.\n"
                                  << ::std::endl;
                        exit(1);
                    }
                    session_ctx[i] =
                        secure_connect_to_server(&s_key_list->s_key[0], ctx);
                    if (session_ctx[i] == NULL) {
                        std::cerr << "Client failed to connect to server in DOS "
                                     "Connect attack.\n"
                                  << ::std::endl;
                        exit(1);
                    }
                    free_session_key_list_t(s_key_list);
                }
            } break;

            case DOSM: {
                // Quantity of send_secure_message requests is the fourth column
                // in the CSV
                int repeat = std::stoi(attack_param);

                // DOS Attack on send_secure_message
                for (int i = 0; i < repeat; ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(
                        1));  // A tiny delay is necessary to give the server
                              // time to read the message;
                    send_secure_message(const_cast<char *>(message.c_str()),
                                        message.length(), session_ctx);
                }
            } break;

            case NONE:
            default:
                break;
        }
    }

    free(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}
