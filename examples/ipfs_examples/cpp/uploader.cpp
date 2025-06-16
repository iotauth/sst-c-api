extern "C" {
    #include <sst-c-api/c_api.h>
    #include "../../../c_common.h"
    #include "../../../c_crypto.h"
    #include "../../../ipfs.h"
}

#include <unistd.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[]) {

    if (argc != 4) {
        std::cerr << "Invalid number of arguments." << std::endl;
        std::cerr << "Correct Usage: " << argv[0] << " <config_path> <my_file_path> <add_reader_path>" << std::endl;
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

    unsigned int hash_length = 0;
    // SHA-256 is 32 bytes
    unsigned char* hash = static_cast<unsigned char*>(std::malloc(32));
    if (!hash) {
        std::cerr << "Allocation failed\n";
        return EXIT_FAILURE;
    }

    digest_message_SHA_256(&file_data[0], filesize, hash, &hash_length);

    std::cout << "Got " << hash_length << " digest bytes\n";

    print_buf_log(hash, hash_length);

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
    unsigned char* received_hash_buf;

    int message_len = -1;
    for (;;) {
        message_len = read_secure_message(session_ctx->sock, &received_hash_buf, session_ctx);
        std::cout << "message_len: " << message_len << std::endl;
        if (message_len > 0) {
            break;
        }
        std::cout << "Did not receive downloader's message yet. Sleeping for 1 second." << std::endl;
        sleep(1);
    }   

    // Step 3: Compare the Hash Values
    // TODO(Carlos Beltran Quinonez): Skip two 4-byte sequence numbers and compare.
    print_buf_log(received_hash_buf, message_len);

    std::cout << reinterpret_cast<char*>(received_hash_buf) << std::endl;

    unsigned char* received_hash = received_hash_buf + 8; // Remove the two 4-byte sequence numbers in the received buffer

    print_buf_log(received_hash, message_len - 8);
    print_buf_log(hash, hash_length);

    if (std::memcmp(hash, received_hash, 32) == 0) {
        std::cout << "Hash values match!" << std::endl;
    } else {
        free(hash);
        free(received_hash_buf);
        std::cerr << "Hash values do not match!" << std::endl;
        return EXIT_FAILURE;
    }
    
    free(received_hash_buf);
    free(hash);
    free_SST_ctx_t(ctx);
    free_session_key_list_t(s_key_list_0);
    close(client_socket);
    close(server_socket);

    return EXIT_SUCCESS;
}


/*
    I don't know what triggers the bug. I want to continue testing to see if there is a pattern.
    Maybe after a certain number of executions? Or maybe after changing the code and recompiling?
    I don't know yet, but I'm really interested in finding out.
    On Monday, I want to follow the code as deep as possible.
    I believe the key is sent in uploader in the upload_to_file_system_manager(), which uses the write_to_socket() function
    and the downloader receives it using receive_data_and_download_file(), which uses the read_from_socket() function.
    I want to look deeper into these functions to see if I can find the root of the problem because
    the problem is that when downloader receives the key, it is an old key that is no longer used.
    Interestingly, the received key is always 5 hex values behind the current one being used by uploader.
    So if uploader sends a key with the last hex being 0x08, the received key will be 0x03.
    Coincidentally, in the config file for uploader it says the number of keys is 5, so this might be linked to the problem.
    But when I brought this up to Dongha, he said this had no effect on the bug. 

    Next Steps: Look into the two functions mentioned. Also, try to find a pattern as to when the bug is triggered.
    Ran it 21 times and it successfully finished 21 times in a row. 
    Recompiled the files and ran it 7 more times, and it successfully finished 7 times in a row.
    Recompiled the files again with these new notes and ran it 2 more times, and it successfully finished 2 times in a row.
    Recompiled only the uploader.cpp file and ran it 3 more times, and it successfully finished 3 times in a row.
*/