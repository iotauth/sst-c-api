/**
 * @file LogManager.h
 * @brief LogManager class definition for managing logging using spdlog.
 * @details
 * This class provides static methods to initialize the logger, set log file paths, and retrieve the logger instance.
 * It also defines a Log class for creating log messages with different log levels.
 * @author Salomon Lee
 * @date 2026-03-26
 */
#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>
#include <map>
#include <string>
#include <sstream>
#include <iostream>
#include <mutex>

/**
 * @class LogManager
 * @brief A singleton class that manages logging using spdlog.
 * @details
 * The LogManager class provides static methods to initialize the logger, set log file paths, and retrieve the logger instance. 
 * It also manages a verbosity flag to control console output of log messages.
 * @note
 * This logger has taken inspiration from the logpp (https://github.com/lsmon/logpp) utilizing
 * spdlog as based logging library.
 */
class LogManager
{
public:
    // Default rotation policy: roll when the active file reaches 50 MB,
    // keep up to 10 rotated backups (≈500 MB raw / ≈50–100 MB compressed by
    // logrotate). Callers can override per-logger.
    static constexpr std::size_t kDefaultMaxSizeBytes = 50ULL * 1024 * 1024;
    static constexpr std::size_t kDefaultMaxFiles = 10;

    /**
     * @brief Initializes the logger with a specified name, file path, and verbosity setting.
     * @param logName       The name of the logger.
     * @param logFilePath   The file path where logs will be written.
     * @param verbose       A boolean flag to enable or disable console output of log messages.
     * @param maxSizeBytes  Maximum size of the active log file before rotation (default 50 MB).
     * @param maxFiles      Number of rotated backups to keep on disk (default 10).
     * @details
     * Uses spdlog::rotating_logger_mt so the log file auto-rotates when it
     * reaches @p maxSizeBytes. When rotation fires, the current file is
     * renamed `<name>.1.log`, the old `.1.log` becomes `.2.log`, etc.; the
     * file at position @p maxFiles is deleted. The active file always keeps
     * its original name (so external tooling and logrotate keep working).
     *
     * If a `logrotate(8)` config also targets the rotated files, they will
     * be gzipped on a separate cadence (recommended: `delaycompress` so the
     * most recent rotated file isn't compressed under an open spdlog handle).
     */
    static void Initialize(
        [[maybe_unused]] const std::string &logName,
        [[maybe_unused]] const std::string &logFilePath,
        [[maybe_unused]] bool verbose = true,
        [[maybe_unused]] std::size_t maxSizeBytes = kDefaultMaxSizeBytes,
        [[maybe_unused]] std::size_t maxFiles = kDefaultMaxFiles);

    /**
     * @brief Sets the log file path for the logger.
     * @param logName       The name of the logger.
     * @param logFilePath   The new file path where logs will be written.
     * @param maxSizeBytes  Maximum size of the active log file before rotation (default 50 MB).
     * @param maxFiles      Number of rotated backups to keep on disk (default 10).
     * @details
     * Re-creates the logger pointing at the new path. The new logger uses
     * the same rotating-file-sink policy as Initialize.
     */
    static void SetLogFilePath(
        [[maybe_unused]] const std::string &logName,
        [[maybe_unused]] const std::string &logFilePath,
        [[maybe_unused]] std::size_t maxSizeBytes = kDefaultMaxSizeBytes,
        [[maybe_unused]] std::size_t maxFiles = kDefaultMaxFiles);
    
    /**
     * @brief Retrieves the logger instance.
     * @return A reference to the spdlog::logger instance.
     * @details
     * This method returns a reference to the logger instance. It assumes that the logger 
     * has been initialized before calling this method.
     */
    static spdlog::logger &GetLogger();

    /**
     * @brief Checks if verbose logging is enabled.
     * @return A boolean indicating whether verbose logging is enabled.
     * @details
     * This method returns the value of the verbosity flag, which controls whether log messages
     * are also printed to the console in addition to being written to the log file.
     */
    static bool IsVerbose();

private:
    static std::shared_ptr<spdlog::logger> logger;
    static bool is_verbose;
};

/**
 * @class Log
 * @brief A class for creating log messages with different log levels.
 * @details
 * The Log class provides a stream-like interface for constructing log messages. 
 * It captures the file name, function name, line number, and log level for each message.
 */
class Log
{
public:
    /**
     * @brief Constructs a log message with the specified file name, function name, 
     * line number, and log level.
     * @param fileName The name of the file where the log message is generated.
     * @param funcName The name of the function where the log message is generated.
     * @param line The line number where the log message is generated.
     * @param l The log level for the message.
     * @details
     * This constructor initializes the log message with contextual information such as the 
     * file name, function name
     */
    Log(
        [[maybe_unused]] const std::string &fileName, 
        [[maybe_unused]] const std::string &funcName, 
        [[maybe_unused]] const long &line, 
        [[maybe_unused]] spdlog::level::level_enum l);

    /**
     * @brief Destroys the log message.
     * @details
     * This destructor cleans up the log message.
     */
    virtual ~Log();

    /**
     * @brief Overloads the stream insertion operator to construct the log message.
     * @tparam T The type of the value being logged.
     * @param v The value to be logged.
     * @return A reference to the Log instance for chaining.
     * @details
     * This operator allows for a stream-like syntax when constructing log messages. 
     * It converts the value to a string and appends it to the log message stream.
     */
    template <class T>
    Log &operator<<(const T &v)
    {
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
// Define macros for logging
#define LOG_INF Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::info)
#define LOG_ERR Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::err)
#define LOG_DBG Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::debug)
#define LOG_TRA Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::trace)
#define LOG_WRN Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::warn)
#define LOG_CRL Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::critical)
#define LOG Log(getFileName(__FILE__), __FUNCTION__, __LINE__, spdlog::level::level_enum::off)

#endif