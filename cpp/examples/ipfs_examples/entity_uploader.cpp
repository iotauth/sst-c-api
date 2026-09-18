/**
 * @file entity_uploader.cpp
 * @brief IPFS uploader built on the SST C++ API.
 *
 * C++ counterpart of examples/ipfs_examples/c/entity_uploader.c. Registers
 * the readers with Auth, gets file sharing session keys, then for each key
 * encrypts the file, adds it to IPFS and registers the CID with the (plain
 * TCP) file system manager.
 */

#include <unistd.h>

#include <chrono>
#include <cstdio>

#include "ipfs_example_common.hpp"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::fprintf(
            stderr,
            "Usage: %s <config_path> <my_file_path> <add_reader_path>\n",
            argv[0]);
        return 1;
    }
    using Clock = std::chrono::steady_clock;
    try {
        sst::SST_API api(argv[1]);
        example::add_readers_from_file(api, argv[3]);

        // Purpose index 1 requests session keys for file sharing.
        auto keygen_start = Clock::now();
        sst::SessionKeyList s_key_list = api.get_session_key_with_index(1);
        float keygen_time =
            std::chrono::duration<float>(Clock::now() - keygen_start).count();
        ::sleep(1);

        for (int i = 0; i < s_key_list.size(); i++) {
            sst::ipfs::estimate_time_t t;
            t.keygenerate_time = i == 0 ? keygen_time : 0;
            std::string hash_value = sst::ipfs::file_encrypt_upload(
                s_key_list.s_key[static_cast<size_t>(i)], api, argv[2], t);
            ::sleep(1);
            auto fm_start = Clock::now();
            sst::ipfs::upload_to_file_system_manager(
                s_key_list.s_key[static_cast<size_t>(i)], api, hash_value);
            t.filemanager_time =
                std::chrono::duration<float>(Clock::now() - fm_start).count();

            std::printf("Time for sending the data to filesystem manager %f\n",
                        t.filemanager_time);
            std::printf("Time for uploading the file to IPFS %f\n",
                        t.up_download_time);
            std::printf("Time for key generation %f\n", t.keygenerate_time);
            std::printf("Time for encrypting the file %f\n", t.enc_dec_time);
            example::append_timing_csv(
                "Upload_result.csv",
                "upload_time,keygenerate_time,enc_time,filemanager_time", t);
            ::sleep(1);
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
