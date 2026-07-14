#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../src/api.hpp"

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
        std::cout << "[1/4] Initializing SST_API..." << std::endl;
        SST_API api(config_path);
        std::cout << "  SST_API initialized successfully." << std::endl;

        std::cout << "[2/4] Performing AUTH_HELLO handshake..." << std::endl;
        api.auth_hello();
        std::cout << "  AUTH_HELLO completed successfully." << std::endl;

        std::cout << "[3/4] Requesting session keys..." << std::endl;
        auto keys = api.get_session_keys("default");
        std::cout << "  Retrieved " << keys.size() << " session key(s)."
                  << std::endl;

        for (size_t i = 0; i < keys.size(); ++i) {
            std::cout << "    Key " << i << " ID: [";
            for (size_t j = 0; j < keys[i].id.size() && j < 8; ++j) {
                printf("%02x", keys[i].id[j]);
            }
            std::cout << "]" << std::endl;
        }

        std::cout << "[4/4] Cleaning up..." << std::endl;
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
