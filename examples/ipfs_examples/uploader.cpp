
extern "C" {
    #include <sst-c-api/c_api.h>
    #include "../../c_crypto.h"
    #include "../../ipfs.h"
}
#include <unistd.h>

int main(int argc, char* argv[]) {
    char* config_path = argv[1];
    char* my_file_path = argv[2];
    char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);

    FILE* add_reader_file = fopen(add_reader_path, "r");
    char addReader[64];
    if (add_reader_file == NULL) {
        fputs("Cannot open file.", stderr);
        fputc('\n', stderr);
        exit(1);
    }
    while (fgets(addReader, sizeof(addReader), add_reader_file) != NULL) {
        send_add_reader_req_via_TCP(ctx, addReader);
    }
    fclose(add_reader_file);
    // Set purpose to make session key request for file sharing.
    ctx->config->purpose_index = 1;
    estimate_time_t estimate_time[5];
    session_key_list_t* s_key_list_0 = get_session_key(ctx, NULL);
    if (s_key_list_0 == NULL) {
        printf("Failed to get session key. Returning NULL.\n");
        exit(1);
    }
    sleep(1);
    unsigned char hash_value[BUFF_SIZE];
    int hash_value_len;

    const char* filename = "Upload_result.csv";
    FILE* file;
    file = fopen(filename, "r");
    if (file) {
        fclose(file);
    } else {
        file = fopen(filename, "w");
        fprintf(
            file,
            "upload_time,keygenerate_time,enc_time,filemanager_time\n");  // columns
        fclose(file);
    }

    file = fopen(filename, "a");
    for (int i = 0; i < ctx->config->numkey; i++) {
        if (i != 0) {
            estimate_time[i].keygenerate_time = 0;
        }
        hash_value_len =
            file_encrypt_upload(&s_key_list_0->s_key[i], ctx, my_file_path,
                                &hash_value[0], &estimate_time[i]);
        sleep(1);
        upload_to_file_system_manager(&s_key_list_0->s_key[i], ctx,
                                      &hash_value[0], hash_value_len);
                                      
        sleep(5);
    }

    // Step 1: Compute Hash of the File
    cout << "Creating hash of the file" << endl;

    // Open the file in binary mode
    file = fopen(my_file_path, "rb");
    if (file == NULL) {
        fputs("Error opening file for hash calculation", stderr);
        fputc('\n', stderr);
        exit(1);
    }

    // Determine the file size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);

    // Allocate buffer to hold the file's data
    unsigned char *file_data = (unsigned char *)malloc(filesize);
    if (file_data == NULL) {
        fputs("Memory allocation error", stderr);
        fputc('\n', stderr);
        fclose(file);
        exit(1);
    }

    // Read the file into the buffer
    size_t read_bytes = fread(file_data, 1, filesize, file);
    if (read_bytes != filesize) {
        fputs("Error reading file", stderr);
        fputc('\n', stderr);
        fclose(file);
        free(file_data);
        exit(1);
    }
    fclose(file);

    // Compute the SHA256 hash of the file data
    unsigned char hash_of_file[SHA256_DIGEST_LENGTH];
    unsigned int hash_length = 0;
    digest_message_SHA_256(file_data, filesize, hash_of_file, &hash_length);

    // Free the buffer as it's no longer needed
    free(file_data);

    // Step 2: Receive Hash from Downloader using Sockets
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        fputs("Error creating socket", stderr);
        fputc('\n', stderr);
        exit(1);
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(9090);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        fputs("Error binding socket", stderr);
        fputc('\n', stderr);
        close(serverSocket);
        exit(1);
    }

    if (listen(serverSocket, 5) < 0) {
        fputs("Error listening on socket", stderr);
        fputc('\n', stderr);
        close(serverSocket);
        exit(1);
    }

    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket < 0) {
        fputs("Error accepting connection", stderr);
        fputc('\n', stderr);
        close(serverSocket);
        exit(1);
    }

    // Expect to receive exactly SHA256_DIGEST_LENGTH bytes from the downloader
    unsigned char received_hash[SHA256_DIGEST_LENGTH];
    int bytes_received = recv(clientSocket, received_hash, SHA256_DIGEST_LENGTH, 0);
    if (bytes_received != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "Expected %d bytes but received %d bytes\n", SHA256_DIGEST_LENGTH, bytes_received);
    }
    close(clientSocket);
    close(serverSocket);

    // Step 3: Compare the Hash Values
    if (memcmp(hash_of_file, received_hash, SHA256_DIGEST_LENGTH) == 0) {
        printf("Hash values are the same.\n");
    } else {
        printf("Hash values are different.\n");
    }
                                                                        

    fclose(file);

    free_SST_ctx_t(ctx);
}