extern "C" {
#include <c/c_api.h>
#include <c/ipfs.h>
}

#include <unistd.h>

#include <fstream>
#include <iostream>
#include <thread>

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
        // Sleep for the specified time
        std::string sleep_time_str = line.substr(0, line.find(','));
        int sleep_time = std::stoi(sleep_time_str);
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));

        // Send message to server
        std::string message = line.substr(line.find(',') + 1);
        send_secure_message(const_cast<char *>(message.c_str()),
                            message.length(), session_ctx);
    }

    free(session_ctx);
    free_session_key_list_t(s_key_list);
    free_SST_ctx_t(ctx);

    return EXIT_SUCCESS;
}
