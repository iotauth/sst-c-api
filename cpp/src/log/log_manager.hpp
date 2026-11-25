/**
 * @file log_manager.hpp
 * @brief Process-wide logging with spdlog and stream-style message builders.
 * @author Salomon Lee
 */
#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <spdlog/spdlog.h>

#include <cstddef>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

/**
 * @brief Manages the shared logger and optional console output.
 * Configure logging before starting worker threads; setup is not synchronized
 * with message dispatch. Inspired by logpp (https://github.com/lsmon/logpp).
 */
class LogManager {
   public:
    // Rotate at 50 MiB and retain up to 10 backups.
    static constexpr std::size_t kDefaultMaxSizeBytes = 50ULL * 1024 * 1024;
    static constexpr std::size_t kDefaultMaxFiles = 10;

    /**
     * @brief Creates a rotating file logger; repeated initialization is
     * ignored. verbose also prints messages to stdout/stderr. Filesystem and
     * spdlog setup errors propagate to the caller.
     */
    static void Initialize(
        [[maybe_unused]] const std::string& logName,
        [[maybe_unused]] const std::string& logFilePath,
        [[maybe_unused]] bool verbose = true,
        [[maybe_unused]] std::size_t maxSizeBytes = kDefaultMaxSizeBytes,
        [[maybe_unused]] std::size_t maxFiles = kDefaultMaxFiles);

    /**
     * @brief Replaces an initialized logger's path and rotation policy.
     * Pass the same logger name used by Initialize(). Does nothing before
     * initialization; preserves the console verbosity setting.
     */
    static void SetLogFilePath(
        [[maybe_unused]] const std::string& logName,
        [[maybe_unused]] const std::string& logFilePath,
        [[maybe_unused]] std::size_t maxSizeBytes = kDefaultMaxSizeBytes,
        [[maybe_unused]] std::size_t maxFiles = kDefaultMaxFiles);

    /** @brief Returns the configured logger, or a fallback stdout logger. */
    static spdlog::logger& GetLogger();
    static bool IsVerbose();

   private:
    static std::shared_ptr<spdlog::logger> logger;
    static bool is_verbose;
};

/**
 * @brief Builds one log entry, including source location and thread ID.
 * The destructor dispatches the completed entry and suppresses logging errors.
 * GIT_VERSION disables dispatch and file setup, but still evaluates streamed
 * arguments and builds the message.
 */
class Log {
   public:
    Log([[maybe_unused]] const std::string& fileName,
        [[maybe_unused]] const std::string& funcName,
        [[maybe_unused]] const long& line,
        [[maybe_unused]] spdlog::level::level_enum l);
    virtual ~Log();

    template <class T>
    Log& operator<<(const T& v) {
        std::stringstream ss;
        ss << v;
        _stream << ss.str();
        return *this;
    }

   private:
    std::stringstream _stream;
    spdlog::level::level_enum _log_level;
    static std::mutex _log_mutex;
};

inline std::string getFileName(const char* filePath) {
    std::string path(filePath);
    size_t lastSlash = path.find_last_of("/\\");
    return (lastSlash == std::string::npos) ? path : path.substr(lastSlash + 1);
}
#define LOG_INF                                        \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::info)
#define LOG_ERR                                        \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::err)
#define LOG_DBG                                        \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::debug)
#define LOG_TRA                                        \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::trace)
#define LOG_WRN                                        \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::warn)
#define LOG_CRL                                        \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::critical)
#define LOG                                            \
    Log(getFileName(__FILE__), __FUNCTION__, __LINE__, \
        spdlog::level::level_enum::off)

#endif
