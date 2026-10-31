#include "../src/ipfs.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "temporary_directory.hpp"

#define CHECK(condition)                                            \
    do {                                                            \
        if (!(condition)) {                                         \
            std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, \
                         #condition);                               \
            std::abort();                                           \
        }                                                           \
    } while (0)

static void test_process_output() {
    // An offline executable exercises the actual fork/exec and output paths.
    const auto executable = std::filesystem::current_path() / "ipfs";
    {
        std::ofstream script(executable);
        script << "#!/bin/sh\n"
                  "case \"$1\" in\n"
                  "  add) [ \"$2\" = --quiet ] && [ -f \"$3\" ] || exit 2\n"
                  "       printf 'TestCID123\\nignored second line\\n' ;;\n"
                  "  cat) [ \"$2\" = TestCID123 ] || exit 3\n"
                  "       printf 'downloaded contents' ;;\n"
                  "  *) exit 4 ;;\n"
                  "esac\n";
        CHECK(script.good());
    }
    std::filesystem::permissions(executable, std::filesystem::perms::owner_all);
    CHECK(::setenv("PATH", std::filesystem::current_path().c_str(), 1) == 0);
    const std::string source = "input file;literal.txt";
    {
        std::ofstream input(source);
    }
    sst::ipfs::estimate_time_t timing;
    CHECK(sst::ipfs::execute_command_and_save_result(source, timing) ==
          "TestCID123");
    bool failed = false;
    try {
        (void)sst::ipfs::execute_command_and_save_result("missing", timing);
    } catch (const sst::SST_Exception&) {
        failed = true;
    }
    CHECK(failed);

    const std::string command = "ipfs cat TestCID123 > ";
    std::vector<unsigned char> response(3 + sst::SESSION_KEY_ID_SIZE +
                                        command.size());
    response[0] = sst::ipfs::DOWNLOAD_RESP;
    response[1] = sst::SESSION_KEY_ID_SIZE;
    response[2 + sst::SESSION_KEY_ID_SIZE - 1] = 42;
    response[2 + sst::SESSION_KEY_ID_SIZE] =
        static_cast<unsigned char>(command.size());
    std::copy_n(command.begin(), command.size(),
                response.begin() + 3 + sst::SESSION_KEY_ID_SIZE);
    std::array<unsigned char, sst::SESSION_KEY_ID_SIZE> key_id{};
    const std::string output = sst::ipfs::download_file(
        response.data(), static_cast<unsigned int>(response.size()),
        key_id.data());
    CHECK(key_id.back() == 42);
    std::ifstream stream(output);
    const std::string contents{std::istreambuf_iterator<char>(stream), {}};
    CHECK(contents == "downloaded contents");
    const auto permissions = std::filesystem::status(output).permissions();
    CHECK((permissions & std::filesystem::perms::all) ==
          (std::filesystem::perms::owner_read |
           std::filesystem::perms::owner_write));
}

int main() {
    const auto previous = std::filesystem::current_path();
    const sst::test::TemporaryDirectory directory{"sst_ipfs_test_"};
    std::filesystem::current_path(directory.path());
    try {
        test_process_output();
    } catch (const std::exception& error) {
        std::filesystem::current_path(previous);
        std::fprintf(stderr, "IPFS test failed: %s\n", error.what());
        return 1;
    }
    std::filesystem::current_path(previous);
    std::puts("IPFS process and output permission tests passed.");
    return 0;
}
