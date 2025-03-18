// g++ -o sha256_hash sha256_hash.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -L/usr/local/lib  -lssl -lcrypto -lsst-c-api

extern "C" {
#include <sst-c-api/c_api.h>
// #include "../../c_crypto.h"
}
// 1. Replace the SHA functions with EVP
// 2. Check entity uploader and downloader files X
//      Understand what it does
// 3. Read the README for examples/file_sharing
#include <iostream>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/err.h>


#define MAX_ERROR_MESSAGE_LENGTH 128

void printf(char *msg) {
    char err[MAX_ERROR_MESSAGE_LENGTH];

    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    exit(1);
}

// void digest_message_SHA_256(unsigned char *data, size_t data_len,
//                             unsigned char *md5_hash, unsigned int *md_len) {
//     EVP_MD_CTX *mdctx;

//     if ((mdctx = EVP_MD_CTX_create()) == NULL) {
//         print_last_error("EVP_MD_CTX_create() failed");
//     }
//     if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
//         print_last_error("EVP_DigestInit_ex failed");
//     }
//     if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
//         print_last_error("EVP_DigestUpdate failed");
//     }
//     if (EVP_DigestFinal_ex(mdctx, md5_hash, md_len) != 1) {
//         print_last_error("failed");
//     }
//     EVP_MD_CTX_destroy(mdctx);
// }

void sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256_CTX sha256;
    // EVP_DigestInit_ex(&sha256);
    // EVP_DigestUpdate(&sha256, input.c_str(), input.size());
    // EVP_DigestFinal_ex(hash, &sha256);

    unsigned char md5_hash[SHA256_DIGEST_LENGTH];
    unsigned int md_len;

    // printf("I am input 1: %s", input.c_str());
    std::cout << "\nI am input 1: " << input << std::endl;

    digest_message_SHA_256((unsigned char*) input.c_str(), input.size(), md5_hash, &md_len);

    std::cout << "Result of hash: " << md5_hash << std::endl;
    
    // printf("I am input: %s", input.c_str());

    // EVP_MD_CTX *mdctx;

    // if ((mdctx = EVP_MD_CTX_create()) == NULL) {
    //     printf("EVP_MD_CTX_create() failed");
    // }
    // if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    //     printf("EVP_DigestInit_ex failed");
    // }
    // if (EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1) {
    //     printf("EVP_DigestUpdate failed");
    // }
    // if (EVP_DigestFinal_ex(mdctx, md5_hash, &md_len) != 1) {
    //     printf("failed");
    // }


    // std::stringstream ss;
    // for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    //     ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    // }
    // return ss.str();
}
int main(int argc, char* argv[]) {
    std::string input;
    std::cout << "Enter a string: ";
    std::getline(std::cin, input);
    sha256(input);
    char* config_path = argv[1];
    // char* my_file_path = argv[2];
    // char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);
    return 0;
}
