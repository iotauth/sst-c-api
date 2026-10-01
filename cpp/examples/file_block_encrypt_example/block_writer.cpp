/**
 * @file block_writer.cpp
 * @brief Encrypts a file block by block with the SST C++ crypto API.
 *
 * Generates a random AES-128 key, saves it to a key file for block_reader,
 * then encrypts the input file in fixed-size blocks. Each encrypted block is
 * written as a record: [IV (16 bytes)][ciphertext length (4 bytes, big
 * endian)][ciphertext].
 *
 * In a full SST deployment the block cipher key comes from a session key
 * issued by Auth; this example derives it locally so it can run standalone.
 */

#include <array>
#include <cstdio>
#include <fstream>

#include "../../src/crypto.hpp"

using sst::Crypto;

namespace {
constexpr unsigned int BLOCK_SIZE = 1024;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::fprintf(stderr,
                     "Usage: %s <plaintext_file> <encrypted_file> <key_file>\n",
                     argv[0]);
        return 1;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input.is_open()) {
        std::fprintf(stderr, "Failed to open plaintext file: %s\n", argv[1]);
        return 1;
    }

    // Generate the AES-128 block cipher key and save it for block_reader.
    std::array<unsigned char, sst::AES_128_KEY_SIZE_IN_BYTES> key{};
    if (Crypto::generate_nonce(static_cast<int>(key.size()), key.data()) != 0) {
        std::fprintf(stderr, "Failed to generate cipher key.\n");
        return 1;
    }
    std::ofstream key_file(argv[3], std::ios::binary);
    if (!key_file.is_open()) {
        std::fprintf(stderr, "Failed to open key file: %s\n", argv[3]);
        return 1;
    }
    key_file.write(reinterpret_cast<const char*>(key.data()), key.size());
    key_file.close();

    std::ofstream output(argv[2], std::ios::binary);
    if (!output.is_open()) {
        std::fprintf(stderr, "Failed to open encrypted file: %s\n", argv[2]);
        return 1;
    }

    std::array<unsigned char, BLOCK_SIZE> plain_block{};
    // CBC padding adds at most one extra cipher block.
    std::array<unsigned char, BLOCK_SIZE + sst::AES_128_CBC_IV_SIZE>
        cipher_block{};
    std::array<unsigned char, sst::AES_128_CBC_IV_SIZE> iv{};

    int block_num = 0;
    while (input) {
        input.read(reinterpret_cast<char*>(plain_block.data()), BLOCK_SIZE);
        std::streamsize plain_length = input.gcount();
        if (plain_length <= 0) {
            break;
        }

        // Fresh random IV per block.
        if (Crypto::generate_nonce(static_cast<int>(iv.size()), iv.data()) !=
            0) {
            std::fprintf(stderr, "Failed to generate IV.\n");
            return 1;
        }

        unsigned int cipher_length = 0;
        if (Crypto::encrypt_aes(plain_block.data(),
                                static_cast<unsigned int>(plain_length),
                                key.data(), iv.data(), sst::AES_128_CBC,
                                cipher_block.data(), &cipher_length) < 0) {
            std::fprintf(stderr, "Failed encrypt_aes() for block %d.\n",
                         block_num);
            return 1;
        }

        // Record: [IV][4-byte big-endian ciphertext length][ciphertext].
        output.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        const unsigned char length_buf[4] = {
            static_cast<unsigned char>((cipher_length >> 24) & 0xFF),
            static_cast<unsigned char>((cipher_length >> 16) & 0xFF),
            static_cast<unsigned char>((cipher_length >> 8) & 0xFF),
            static_cast<unsigned char>(cipher_length & 0xFF)};
        output.write(reinterpret_cast<const char*>(length_buf), 4);
        output.write(reinterpret_cast<const char*>(cipher_block.data()),
                     cipher_length);

        std::printf("Wrote encrypted block %d (%u bytes)\n", block_num,
                    cipher_length);
        block_num++;
    }

    std::printf("Finished writing %d encrypted block(s) to %s\n", block_num,
                argv[2]);
    return 0;
}
