/**
 * @file ipfs_example_common.hpp
 * @brief Small helpers shared by the C++ IPFS example programs.
 */

#ifndef SST_IPFS_EXAMPLE_COMMON_HPP
#define SST_IPFS_EXAMPLE_COMMON_HPP

#include <cstdio>
#include <fstream>
#include <string>

#include "../../src/api.hpp"
#include "../../src/ipfs.hpp"

namespace example {

// Sends one ADD_READER request to Auth per non-empty line of the file.
inline void add_readers_from_file(sst::SST_API& api,
                                  const std::string& add_reader_path) {
    std::ifstream add_reader_file(add_reader_path);
    if (!add_reader_file.is_open()) {
        throw sst::SST_Exception("Cannot open add reader file: " +
                                 add_reader_path);
    }
    std::string line;
    while (std::getline(add_reader_file, line)) {
        size_t end = line.find_last_not_of(" \t\r\n");
        if (end == std::string::npos) continue;
        line.erase(end + 1);
        api.send_add_reader_req_via_TCP(line);
    }
}

// Appends one timing row to a CSV file, writing the header when the file is
// new.
inline void append_timing_csv(const std::string& file_name,
                              const std::string& header,
                              const sst::ipfs::estimate_time_t& t) {
    bool exists = std::ifstream(file_name).good();
    std::ofstream out(file_name, std::ios::app);
    if (!exists) {
        out << header << "\n";
    }
    char row[128];
    std::snprintf(row, sizeof(row), "%.6f,%.6f,%.6f,%.6f", t.up_download_time,
                  t.keygenerate_time, t.enc_dec_time, t.filemanager_time);
    out << row << "\n";
}

}  // namespace example

#endif  // SST_IPFS_EXAMPLE_COMMON_HPP
