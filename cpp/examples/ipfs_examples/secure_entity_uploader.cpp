/**
 * @file secure_entity_uploader.cpp
 * @brief IPFS uploader that talks to the secure file system manager over an
 * SST session.
 *
 * C++ counterpart of examples/ipfs_examples/c/secure_entity_uploader.c.
 * Registers the readers with Auth, encrypts and uploads the file with a file
 * sharing session key, then sends the CID and key ID to the secure file
 * system manager through a secure session established with a second session
 * key.
 */

#include <unistd.h>

#include <cstdio>
#include <thread>

#include "ipfs_example_common.hpp"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::fprintf(
            stderr,
            "Usage: %s <config_path> <my_file_path> <add_reader_path>\n",
            argv[0]);
        return 1;
    }
    try {
        sst::SST_API api(argv[1]);
        example::add_readers_from_file(api, argv[3]);

        // Purpose index 1 requests session keys for file sharing.
        sst::SessionKeyList s_key_list_0 = api.get_session_key_with_index(1);
        if (s_key_list_0.empty()) {
            std::fprintf(stderr, "No file sharing session key received.\n");
            return 1;
        }
        sst::ipfs::estimate_time_t t;
        std::string hash_value = sst::ipfs::file_encrypt_upload(
            s_key_list_0.s_key[0], api, argv[2], t);
        std::printf(
            "FileSharing session key ID to upload: %llu\n",
            static_cast<unsigned long long>(sst::convert_skid_buf_to_int(
                s_key_list_0.s_key[0].key_id, sst::SESSION_KEY_ID_SIZE)));
        std::vector<unsigned char> upload_req =
            sst::ipfs::make_upload_req_buffer(s_key_list_0.s_key[0], api,
                                              hash_value);

        // Purpose index 0 requests the session key for the file system
        // manager.
        sst::SessionKeyList s_key_list = api.get_session_key_with_index(0);
        if (s_key_list.empty()) {
            std::fprintf(stderr, "No file system manager session key.\n");
            return 1;
        }
        auto session = api.secure_connect_to_server(s_key_list.s_key[0]);
        ::sleep(1);
        std::thread receiver([&session] { session->receive_loop(); });
        // The receiver must be shut down and joined on every path, so
        // remember failures instead of returning early.
        bool sent = session->send_secure_message("Hello") >= 0;
        if (sent) {
            ::sleep(1);
            sent = session->send_secure_message(
                       upload_req.data(),
                       static_cast<unsigned int>(upload_req.size())) >= 0;
        }
        if (sent) {
            ::sleep(1);
        }
        session->shutdown();
        receiver.join();
        if (!sent) {
            std::fprintf(stderr, "Failed send_secure_message().\n");
            return 1;
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
