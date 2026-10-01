/**
 * @file secure_entity_downloader.cpp
 * @brief IPFS downloader that talks to the secure file system manager over an
 * SST session.
 *
 * C++ counterpart of examples/ipfs_examples/c/secure_entity_downloader.c.
 * Asks the secure file system manager for the file information over a secure
 * session, downloads the file from IPFS, gets its session key from Auth by
 * ID and decrypts it.
 */

#include <unistd.h>

#include <cstdio>

#include "ipfs_example_common.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <config_file_path>\n", argv[0]);
        return 1;
    }
    try {
        sst::SST_API api(argv[1]);
        sst::SessionKeyList s_key_list;

        // Purpose index 0 requests the session key for the file system
        // manager.
        sst::SessionKeyList s_key_list_0 = api.get_session_key_with_index(0);
        if (s_key_list_0.empty()) {
            std::fprintf(stderr, "No file system manager session key.\n");
            return 1;
        }
        auto session = api.secure_connect_to_server(s_key_list_0.s_key[0]);
        ::sleep(3);
        std::vector<unsigned char> download_req =
            sst::ipfs::make_download_req_buffer(api);
        if (session->send_secure_message(
                download_req.data(),
                static_cast<unsigned int>(download_req.size())) < 0) {
            std::fprintf(stderr, "Failed send_secure_message().\n");
            return 1;
        }
        unsigned char decrypted[sst::MAX_SECURE_COMM_MSG_LENGTH];
        int len = session->read_secure_message(decrypted, sizeof(decrypted));
        if (len <= 0) {
            std::fprintf(stderr, "Failed read_secure_message().\n");
            return 1;
        }
        if (decrypted[0] != sst::ipfs::DOWNLOAD_RESP) {
            std::fprintf(stderr, "Not a download response!\n");
            return 1;
        }
        std::printf("Session key id size: %d\n", decrypted[1]);
        std::printf("Command size: %d\n",
                    decrypted[sst::SESSION_KEY_ID_SIZE + 2]);

        unsigned char received_skey_id[sst::SESSION_KEY_ID_SIZE];
        std::string file_name = sst::ipfs::download_file(
            decrypted, static_cast<unsigned int>(len), received_skey_id);
        sst::session_key_t* session_key =
            api.get_session_key_by_ID(received_skey_id, s_key_list);
        ::sleep(1);
        sst::ipfs::file_decrypt_save(*session_key, file_name);
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
