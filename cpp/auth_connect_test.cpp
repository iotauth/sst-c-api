/**
 * @file auth_connect_test.cpp
 * @brief Integration test: requests session keys from Auth via sst-cpp-api.
 *
 * Tests:
 * 1. SST_API initialization with a valid config
 * 2. Session key request (AUTH_HELLO / SESSION_KEY_REQ / SESSION_KEY_RESP)
 * 3. Connection cleanup
 */

#include <cstdio>
#include <iostream>
#include <string>

#include "src/api.hpp"

using sst::SST_API;
using sst::SST_Exception;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    std::string config_path = argv[1];
    std::cout << "=== SST C++ API Auth Connection Test ===" << std::endl;
    std::cout << "Config: " << config_path << std::endl;
    std::cout << std::endl;

    try {
        std::cout << "[1/3] Initializing SST_API..." << std::endl;
        SST_API api(config_path);
        std::cout << "  SST_API initialized successfully." << std::endl;

        std::cout << "[2/3] Requesting session keys from Auth..." << std::endl;
        sst::SessionKeyList keys = api.get_session_key();
        std::cout << "  Retrieved " << keys.size() << " session key(s)."
                  << std::endl;
        for (int i = 0; i < keys.size(); ++i) {
            std::cout << "    Key " << i << " ID: [";
            for (unsigned int j = 0; j < sst::SESSION_KEY_ID_SIZE; ++j) {
                std::printf("%02x", keys.s_key[i].key_id[j]);
            }
            std::cout << "]" << std::endl;
        }

        std::cout << "[3/3] Cleaning up..." << std::endl;
        std::cout << std::endl;
        std::cout << "=== Auth connection test PASSED ===" << std::endl;
        return 0;
    } catch (const SST_Exception& e) {
        std::cerr << std::endl;
        std::cerr << "=== Auth connection test FAILED ===" << std::endl;
        std::cerr << "SST_Exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << std::endl;
        std::cerr << "=== Auth connection test FAILED ===" << std::endl;
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}
