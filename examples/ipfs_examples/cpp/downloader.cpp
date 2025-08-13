extern "C" {
#include "../../../c_crypto.h"
#include "../../../ipfs.h"
}

#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

// Checks if the file exists by attempting to open it in read mode.
bool fileExists(const std::string &filename) {
    FILE *file = fopen(filename.c_str(), "r");
    if (file) {
        fclose(file);
        return true;
    }
    return false;
}

// Checks what the next available filename is by appending a number to the base
// name.
std::string getAvailableFilename(const std::string &baseName,
                                 const std::string &extension) {
    std::string filename = baseName + extension;
    if (!fileExists(filename)) {
        return filename;
    }

    int counter = 0;
    while (true) {
        filename = baseName + std::to_string(counter) + extension;
        if (!fileExists(filename)) {
            return filename;
        }
        ++counter;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Invalid number of arguments." << std::endl;
        std::cerr << "Correct Usage: " << argv[0] << " <config_path>"
                  << std::endl;
        return EXIT_FAILURE;
    }

    std::string config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path.c_str());
    if (ctx == NULL) {
        SST_print_error_exit("init_SST() failed.");
    }
    session_key_list_t *s_key_list = init_empty_session_key_list();
    ctx->config->purpose_index = 0;
    std::vector<char> file_name(BUFF_SIZE);
    std::vector<unsigned char> received_skey_id(SESSION_KEY_ID_SIZE);
    estimate_time_t estimate_time[5];

    if (receive_data_and_download_file(received_skey_id.data(), ctx,
                                       file_name.data(),
                                       &estimate_time[0]) < 0) {
        SST_print_error_exit("Failed receive_data_and_download_file().");
    }

    session_key_t *session_key =
        get_session_key_by_ID(received_skey_id.data(), ctx, s_key_list);

    if (session_key == NULL) {
        std::cerr << "Failed to get_session_key_by_ID()." << std::endl;
        return EXIT_FAILURE;
    }

    // Check the latest result file, e.g., result25.txt.
    // Before creating the new "result.txt" file, get the file name
    std::string base = "result";
    std::string ext = ".txt";

    std::string available_filename = getAvailableFilename(base, ext);

    if (file_decrypt_save(*session_key, file_name.data()) < 0) {
        SST_print_error_exit("Failed file_decrypt_save()");
    }

    // Step 1. Create Hash

    // Open the file in binary read mode
    std::ifstream file(available_filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error opening file for hash calculation" << std::endl;
        return EXIT_FAILURE;
    }

    // Determine file size
    std::streamsize filesize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the file data into the vector
    std::vector<unsigned char> file_data(filesize);
    if (!file.read(reinterpret_cast<char *>(file_data.data()), filesize)) {
        std::cerr << "Error reading file" << std::endl;
        return EXIT_FAILURE;
    }
    file.close();

    // Compute the hash
    std::vector<unsigned char> hash_of_file(SHA256_DIGEST_LENGTH);
    unsigned int hash_length = 0;
    if (digest_message_SHA_256(reinterpret_cast<unsigned char *>(&file_data[0]),
                               filesize, hash_of_file.data(),
                               &hash_length) < 0) {
        SST_print_error_exit("Failed digest_message_SHA_256().");
    }

    // Step 2. Send hash to uploader
    // Send the computed hash (raw bytes)
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    if (session_ctx == NULL) {
        SST_print_error_exit("Failed secure_connect_to_server().");
    }
    int msg = send_secure_message(reinterpret_cast<char *>(hash_of_file.data()),
                                  hash_length, session_ctx);
    if (msg < 0) {
        SST_print_error_exit("Failed send_secure_message().");
    }

    free_SST_ctx_t(ctx);
    free_session_key_list_t(s_key_list);

    return EXIT_SUCCESS;
}
