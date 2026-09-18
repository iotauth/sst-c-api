/**
 * @file threaded_get_target_id_client.cpp
 * @brief Gets multiple session keys and saves each key ID to a metadata file.
 *
 * C++ counterpart of
 * examples/server_client_example/threaded_get_target_id_client.c.
 */

#include <cstdio>
#include <fstream>

#include "../../src/api.hpp"

namespace {

bool write_session_key_id_to_file(const sst::session_key_t& s_key,
                                  const char* file_path) {
    std::ofstream fp(file_path, std::ios::binary);
    if (!fp.is_open()) {
        std::fprintf(stderr, "Error: Could not open file %s for writing\n",
                     file_path);
        return false;
    }
    // reinterpret_cast: ofstream writes char buffers.
    fp.write(reinterpret_cast<const char*>(s_key.key_id),
             sst::SESSION_KEY_ID_SIZE);
    return fp.good();
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <config_path>\n", argv[0]);
        return 1;
    }
    try {
        sst::SST_API api(argv[1]);
        sst::SessionKeyList s_key_list = api.get_session_key();

        const char* file_paths[] = {"s_key_id0.dat", "s_key_id1.dat",
                                    "s_key_id2.dat"};
        if (s_key_list.size() < 3) {
            std::fprintf(stderr, "Expected 3 session keys, got %d.\n",
                         s_key_list.size());
            return 1;
        }
        for (size_t i = 0; i < 3; i++) {
            if (!write_session_key_id_to_file(s_key_list.s_key[i],
                                              file_paths[i])) {
                return 1;
            }
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
