extern "C" {
#include "../../c_api.h"
// #include "../../ipfs.h"
}

#include <unistd.h>

#include <fstream>
#include <iostream>
#include <thread>

enum AttackType {
    NONE,
    REPLAY,
    DOS
};

static AttackType parseAttackType(const std::string& s) {
    if (s == "REPLAY" || s == "Replay" || s == "replay") return REPLAY;
    if (s == "DOS" || s == "DoS" || s == "dos") return DOS;
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
        std::cerr << "Failed to get session key. Returning NULL.\n"
                  << ::std::endl;
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
        std::string attack_type_str = (comma2 != std::string::npos)
        ? line.substr(comma2 + 1, (comma3 == std::string::npos ? std::string::npos : comma3 - comma2 - 1)) // if there is a 3rd column, grab it
        : ""; // else, use the empty string

        AttackType attack_type = parseAttackType(attack_type_str);

        // Optional: parameter for the attack type if applicable
        std::string attack_param = (comma3 != std::string::npos)
        ? line.substr(comma3 + 1)
        : "";

        switch (attack_type) {
            case REPLAY:
                if      (attack_param == "seq--") {
                    session_ctx->sent_seq_num--;
                }
                else if (attack_param == "seq++") {
                    session_ctx->sent_seq_num++;
                }
                else if (attack_param.rfind("seq=", 0) == 0) {
                    // parse “seq=#”
                    int v = std::stoi(attack_param.substr(4));
                    session_ctx->sent_seq_num = v;
                }
                break;

            case DOS: {
                // interpret attack_param as an integer
                int repeat = std::stoi(attack_param);

                // DOS Attack
                for (int i = 0; i < repeat; ++i) {
                    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
                }
                break;
            }

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
