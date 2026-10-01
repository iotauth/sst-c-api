/**
 * @file block_reader.cpp
 * @brief Decrypts a file produced by block_writer and verifies its content.
 *
 * Reads [IV][length][ciphertext] records from the encrypted file, decrypts
 * each block with the key saved by block_writer, writes the recovered
 * plaintext, and (optionally) compares each block against the original file.
 */

#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>

#include "../../src/crypto.hpp"

using sst::Crypto;

namespace {
constexpr unsigned int BLOCK_SIZE = 1024;
}

int main(int argc, char* argv[]) {
    if (argc != 4 && argc != 5) {
        std::fprintf(stderr,
                     "Usage: %s <encrypted_file> <key_file> <decrypted_file> "
                     "[original_file]\n",
                     argv[0]);
        return 1;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input.is_open()) {
        std::fprintf(stderr, "Failed to open encrypted file: %s\n", argv[1]);
        return 1;
    }

    std::ifstream key_file(argv[2], std::ios::binary);
    if (!key_file.is_open()) {
        std::fprintf(stderr, "Failed to open key file: %s\n", argv[2]);
        return 1;
    }
    std::array<unsigned char, sst::AES_128_KEY_SIZE_IN_BYTES> key{};
    key_file.read(reinterpret_cast<char*>(key.data()), key.size());
    if (key_file.gcount() != static_cast<std::streamsize>(key.size())) {
        std::fprintf(stderr, "Key file too short: %s\n", argv[2]);
        return 1;
    }

    std::ofstream output(argv[3], std::ios::binary);
    if (!output.is_open()) {
        std::fprintf(stderr, "Failed to open decrypted file: %s\n", argv[3]);
        return 1;
    }

    const bool check_original = (argc == 5);
    std::ifstream original;
    if (check_original) {
        original.open(argv[4], std::ios::binary);
        if (!original.is_open()) {
            std::fprintf(stderr, "Failed to open original file: %s\n", argv[4]);
            return 1;
        }
    }

    std::array<unsigned char, sst::AES_128_CBC_IV_SIZE> iv{};
    std::array<unsigned char, BLOCK_SIZE + sst::AES_128_CBC_IV_SIZE>
        cipher_block{};
    std::array<unsigned char, BLOCK_SIZE + sst::AES_128_CBC_IV_SIZE>
        plain_block{};
    std::array<unsigned char, BLOCK_SIZE> original_block{};

    int block_num = 0;
    while (input.read(reinterpret_cast<char*>(iv.data()), iv.size())) {
        unsigned char length_buf[4];
        if (!input.read(reinterpret_cast<char*>(length_buf), 4)) {
            std::fprintf(stderr, "Truncated record header in block %d.\n",
                         block_num);
            return 1;
        }
        const unsigned int cipher_length =
            (static_cast<unsigned int>(length_buf[0]) << 24) |
            (static_cast<unsigned int>(length_buf[1]) << 16) |
            (static_cast<unsigned int>(length_buf[2]) << 8) |
            static_cast<unsigned int>(length_buf[3]);
        if (cipher_length == 0 || cipher_length > cipher_block.size()) {
            std::fprintf(stderr, "Invalid ciphertext length %u in block %d.\n",
                         cipher_length, block_num);
            return 1;
        }
        if (!input.read(reinterpret_cast<char*>(cipher_block.data()),
                        cipher_length)) {
            std::fprintf(stderr, "Truncated ciphertext in block %d.\n",
                         block_num);
            return 1;
        }

        unsigned int plain_length = 0;
        if (Crypto::decrypt_aes(cipher_block.data(), cipher_length, key.data(),
                                iv.data(), sst::AES_128_CBC, plain_block.data(),
                                &plain_length) < 0) {
            std::fprintf(stderr, "Failed decrypt_aes() for block %d.\n",
                         block_num);
            return 1;
        }

        output.write(reinterpret_cast<const char*>(plain_block.data()),
                     plain_length);

        if (check_original) {
            original.read(reinterpret_cast<char*>(original_block.data()),
                          plain_length);
            if (original.gcount() !=
                    static_cast<std::streamsize>(plain_length) ||
                std::memcmp(original_block.data(), plain_block.data(),
                            plain_length) != 0) {
                std::fprintf(stderr,
                             "Block %d does not match the original file!\n",
                             block_num);
                return 1;
            }
            std::printf(
                "Checked block %d. Decrypted block and original plaintext are "
                "same!\n",
                block_num);
        }
        block_num++;
    }

    std::printf("Finished decrypting %d block(s) to %s\n", block_num, argv[3]);
    return 0;
}
