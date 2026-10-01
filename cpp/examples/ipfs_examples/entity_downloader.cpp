/**
 * @file entity_downloader.cpp
 * @brief IPFS downloader built on the SST C++ API.
 *
 * C++ counterpart of examples/ipfs_examples/c/entity_downloader.c. Three
 * times in a row it asks the (plain TCP) file system manager for a file,
 * downloads it from IPFS, gets the file's session key from Auth by ID and
 * decrypts it.
 */

#include <unistd.h>

#include <chrono>
#include <cstdio>

#include "ipfs_example_common.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <config_file_path>\n", argv[0]);
        return 1;
    }
    using Clock = std::chrono::steady_clock;
    try {
        sst::SST_API api(argv[1]);
        sst::SessionKeyList s_key_list;

        for (int i = 0; i < 3; i++) {
            sst::ipfs::estimate_time_t t;
            unsigned char received_skey_id[sst::SESSION_KEY_ID_SIZE];
            std::string file_name = sst::ipfs::receive_data_and_download_file(
                received_skey_id, api, t);

            auto keygen_start = Clock::now();
            sst::session_key_t* session_key =
                api.get_session_key_by_ID(received_skey_id, s_key_list);
            t.keygenerate_time =
                std::chrono::duration<float>(Clock::now() - keygen_start)
                    .count();

            ::sleep(1);
            auto decrypt_start = Clock::now();
            sst::ipfs::file_decrypt_save(*session_key, file_name);
            t.enc_dec_time =
                std::chrono::duration<float>(Clock::now() - decrypt_start)
                    .count();

            std::printf(
                "Time for receiving the data from filesystem manager %f\n",
                t.filemanager_time);
            std::printf("Time for downloading the file from IPFS %f\n",
                        t.up_download_time);
            std::printf("Time for key generation %f\n", t.keygenerate_time);
            std::printf("Time for decrypting the file %f\n", t.enc_dec_time);
            example::append_timing_csv(
                "Download_result.csv",
                "download_time,keygenerate_time,dec_time,filemanager_time", t);
            ::sleep(1);
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
