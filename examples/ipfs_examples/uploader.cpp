// Compile:
// g++ -o uploader uploader.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -L/usr/local/lib  -lssl -lcrypto -lsst-c-api

// Execute:
// ./uploader uploader_copy.config plain_text.txt addReader.txt
extern "C" {
    #include <sst-c-api/c_api.h>
    #include "../../c_crypto.h"
    #include "../../ipfs.h"
}

#include <unistd.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[]) {

    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <config_path> <my_file_path> <add_reader_path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string config_path = argv[1];
    std::string my_file_path = argv[2];
    std::string add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path.c_str());

    std::ifstream add_reader_file(add_reader_path);
    if (!add_reader_file) {
        std::cerr << "Cannot open add_reader file." << std::endl;
        return EXIT_FAILURE;
    }

    std::string add_reader;
    while (std::getline(add_reader_file, add_reader)) {
        send_add_reader_req_via_TCP(ctx, const_cast<char*>(add_reader.c_str()));
    }
    add_reader_file.close();

    // Set purpose to make session key request for file sharing.
    ctx->config->purpose_index = 1;
    estimate_time_t estimate_time[5];
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    if (s_key_list_0 == NULL) {
        std::cerr << "Failed to get session key. Returning NULL." << std::endl;
        return EXIT_FAILURE;
    }
    sleep(1);

    std::vector<unsigned char> hash_value(BUFF_SIZE);
    int hash_value_len;

    hash_value_len =
        file_encrypt_upload(&s_key_list_0->s_key[0], ctx, const_cast<char*>(my_file_path.c_str()),
                            &hash_value[0], &estimate_time[0]);
    sleep(1);
    upload_to_file_system_manager(&s_key_list_0->s_key[0], ctx,
                                    &hash_value[0], hash_value_len);
                                    
    sleep(5);

    // Step 1: Compute Hash of the File

    // Open the file in binary mode
    std::ifstream file(my_file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error opening file for hash calculation" << std::endl;
        return EXIT_FAILURE;
    }

    // Determine the file size
    std::streamsize filesize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file data into a vector
    std::vector<unsigned char> file_data(filesize);
    if (!file.read(reinterpret_cast<char*>(file_data.data()), filesize)) {
        std::cerr << "Error reading file" << std::endl;
        return EXIT_FAILURE;
    }
    file.close();

    // Compute the SHA256 hash of the file data
    std::vector<unsigned char> hash_of_file(SHA256_DIGEST_LENGTH);
    unsigned int hash_length = 0;
    digest_message_SHA_256(&file_data[0], filesize, hash_of_file.data(), &hash_length);

    // Step 2: Receive Hash from Downloader using Sockets
    
    int server_socket = socket(PF_INET, SOCK_STREAM, 0);

    if (server_socket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return EXIT_FAILURE;
    }

        // Allow reuse of the local address (port) even if it’s in TIME_WAIT
        int reuse = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            std::perror("setsockopt(SO_REUSEADDR) failed"); // Non‐fatal: we can still proceed, but bind might fail.
        }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(21100);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Error binding socket: " << std::strerror(errno) << std::endl;
        close(server_socket);
        return EXIT_FAILURE;
    }

    if (listen(server_socket, 5) < 0) {
        std::cerr << "Error listening on socket" << std::endl;
        close(server_socket);
        return EXIT_FAILURE;
    }

    std::cout << "Waiting for client to connect..." << std::endl;

    int client_socket = accept(server_socket, nullptr, nullptr);
    if (client_socket < 0) {
        std::cerr << "Error accepting connection" << std::endl;
        close(server_socket);
        return EXIT_FAILURE;
    }
    std::cout << "Client Socket Accepted Connection." << std::endl;
    
    SST_session_ctx_t *session_ctx = server_secure_comm_setup(ctx, client_socket, s_key_list_0);
    std::cout << "Checkpoint 2" << std::endl;

    if (session_ctx == NULL) {
        std::cerr << "There is no session key.\n" << std::endl;
        return EXIT_FAILURE;
    }

    // Receive the hash

    std::vector<unsigned char> received_hash(SHA256_DIGEST_LENGTH);
    unsigned char *received_hash_data = received_hash.data();
    read_secure_message(session_ctx->sock, &received_hash_data, session_ctx);

    // Step 3: Compare the Hash Values
    if (hash_of_file == received_hash) {
        std::cout << "Hash values are the same." << std::endl;
    } else {
        std::cout << "Hash values are different." << std::endl;
    }
                                                                        
    free_SST_ctx_t(ctx);
    free_session_key_list_t(s_key_list_0);
    close(client_socket);
    close(server_socket);

    return EXIT_SUCCESS;
}