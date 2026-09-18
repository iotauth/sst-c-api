/**
 * @file threaded_get_target_id_server.cpp
 * @brief Multi-threaded retrieval of session keys by ID.
 *
 * C++ counterpart of
 * examples/server_client_example/threaded_get_target_id_server.c. Each
 * thread reads a session key ID from a metadata file and requests that key
 * from Auth through the shared SST_API instance, whose internal mutex makes
 * the concurrent requests thread-safe.
 */

#include <atomic>
#include <cstdio>
#include <fstream>
#include <thread>
#include <vector>

#include "../../src/api.hpp"

namespace {

void call_get_session_key_by_ID(sst::SST_API& api, const char* file_path,
                                std::atomic<int>& failures) {
    unsigned char target_session_key_id[sst::SESSION_KEY_ID_SIZE];
    std::ifstream fp(file_path, std::ios::binary);
    if (!fp.is_open()) {
        std::fprintf(stderr, "Error: Could not open file %s\n", file_path);
        failures++;
        return;
    }
    // reinterpret_cast: ifstream reads into char buffers.
    fp.read(reinterpret_cast<char*>(target_session_key_id),
            sst::SESSION_KEY_ID_SIZE);
    if (fp.gcount() != static_cast<std::streamsize>(sst::SESSION_KEY_ID_SIZE)) {
        std::fprintf(stderr, "Error: Could not read key ID from %s\n",
                     file_path);
        failures++;
        return;
    }
    std::printf("Session Key ID from file %s: %llu\n", file_path,
                static_cast<unsigned long long>(sst::convert_skid_buf_to_int(
                    target_session_key_id, sst::SESSION_KEY_ID_SIZE)));

    sst::SessionKeyList s_key_list;
    try {
        sst::session_key_t* session_key =
            api.get_session_key_by_ID(target_session_key_id, s_key_list);
        std::printf("Retrieved Session Key ID: %llu\n",
                    static_cast<unsigned long long>(
                        sst::convert_skid_buf_to_int(
                            session_key->key_id, sst::SESSION_KEY_ID_SIZE)));
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr,
                     "Error: Failed to retrieve session key for %s: %s\n",
                     file_path, e.what());
        failures++;
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <config_path>\n", argv[0]);
        return 1;
    }
    try {
        sst::SST_API api(argv[1]);
        const char* file_paths[] = {"s_key_id0.dat", "s_key_id1.dat",
                                    "s_key_id2.dat"};
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        for (const char* file_path : file_paths) {
            threads.emplace_back(call_get_session_key_by_ID, std::ref(api),
                                 file_path, std::ref(failures));
        }
        for (auto& t : threads) {
            t.join();
        }
        if (failures > 0) {
            return 1;
        }
    } catch (const sst::SST_Exception& e) {
        std::fprintf(stderr, "SST error: %s\n", e.what());
        return 1;
    }
    return 0;
}
