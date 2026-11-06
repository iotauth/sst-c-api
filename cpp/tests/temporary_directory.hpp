#ifndef SST_TEST_TEMPORARY_DIRECTORY_HPP
#define SST_TEST_TEMPORARY_DIRECTORY_HPP

#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

namespace sst::test {

// CTest runs in the build directory. Keep test credentials there in a fresh,
// owner-only directory instead of selecting a shared system temporary path.
class TemporaryDirectory {
   public:
    explicit TemporaryDirectory(const std::string& prefix)
        : pattern_((std::filesystem::current_path() / (prefix + "XXXXXX"))
                       .string()) {
        // mkdtemp atomically creates the directory with mode 0700 and refuses
        // existing names, including symlinks. Never chmod a reused directory.
        if (::mkdtemp(pattern_.data()) == nullptr) {
            throw std::system_error(errno, std::generic_category(), "mkdtemp");
        }
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(pattern_, ignored);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    std::filesystem::path path() const { return pattern_; }

   private:
    std::string pattern_;
};

}  // namespace sst::test

#endif  // SST_TEST_TEMPORARY_DIRECTORY_HPP
