extern "C" {
#include <sst-c-api/c_api.h>
}

#include <iostream>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}
int main(int argc, char* argv[]) {
    std::string input;
    std::cout << "Enter a string: ";
    std::getline(std::cin, input);
    std::cout << "SHA-256: " << sha256(input) << std::endl;

    char* config_path = argv[1];
    // char* my_file_path = argv[2];
    // char* add_reader_path = argv[3];
    SST_ctx_t* ctx = init_SST(config_path);
    return 0;
}
