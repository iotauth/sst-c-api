#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include <filesystem>
#include <iostream>
#include "log_manager.hpp"

// Add this line to define the static mutex
std::mutex Log::_log_mutex;
std::shared_ptr<spdlog::logger> LogManager::logger = nullptr;
bool LogManager::is_verbose = false; // Definition


void LogManager::Initialize(
    [[maybe_unused]] const std::string &logName,
    [[maybe_unused]] const std::string &logFilePath,
    [[maybe_unused]] bool verbose,
    [[maybe_unused]] std::size_t maxSizeBytes,
    [[maybe_unused]] std::size_t maxFiles)
{
#ifndef GIT_VERSION
    if (logger)
    {
        LOG_DBG << "Logger already initialized. Skipping re-initialization.";
        return;
    }
    // Ensure the logs directory exists
    std::filesystem::path log_dir = logFilePath;
    log_dir.remove_filename();
    if (!std::filesystem::exists(log_dir))
    {
        std::filesystem::create_directories(log_dir);
    }

    // Rotating sink: when the active file hits maxSizeBytes spdlog rotates
    // it to <name>.1.log, shifts the others down, and deletes anything
    // beyond maxFiles. This keeps disk usage bounded without any external
    // tooling. If logrotate is configured to gzip the rotated files, those
    // archives end up gzipped on its own schedule (delaycompress recommended
    // so the most-recent rotated file isn't compressed while spdlog might
    // still hold a handle to it during the next rotation).
    logger = spdlog::rotating_logger_mt(logName, logFilePath, maxSizeBytes, maxFiles);
#endif
    is_verbose = verbose;
}

void LogManager::SetLogFilePath(
    [[maybe_unused]] const std::string &logName,
    [[maybe_unused]] const std::string &logFilePath,
    [[maybe_unused]] std::size_t maxSizeBytes,
    [[maybe_unused]] std::size_t maxFiles)
{
#ifndef GIT_VERSION
    if (logger)
    {
        // Ensure the logs directory exists
        std::filesystem::path log_dir = logFilePath;
        log_dir.remove_filename();
        if (!std::filesystem::exists(log_dir))
        {
            std::filesystem::create_directories(log_dir);
        }

        // spdlog refuses to register the same logger name twice. Drop the
        // existing logger before re-creating with the new path/policy.
        spdlog::drop(logName);
        logger = spdlog::rotating_logger_mt(logName, logFilePath, maxSizeBytes, maxFiles);
    }
#endif
}

spdlog::logger &LogManager::GetLogger()
{
    if (!logger)
    {
        // Create a default stdout logger if none exists to prevent crashes.
        static std::shared_ptr<spdlog::logger> default_logger = spdlog::stdout_color_mt("default");
        return *default_logger;
    }
    return *logger;
}

bool LogManager::IsVerbose()
{
    return is_verbose;
}

Log::Log(
    [[maybe_unused]] const std::string &fileName, 
    [[maybe_unused]] const std::string &funcName, 
    [[maybe_unused]] const long &line, 
    [[maybe_unused]] spdlog::level::level_enum l)
{
#ifndef GIT_VERSION
    std::thread::id tid = std::this_thread::get_id();
    std::stringstream ss_tid;
    ss_tid << tid; 
    _log_level = l;
    
    _stream << " [" << fileName << "::" << funcName << "(" << line << ")] (thxid: " << ss_tid.str() << ") - ";
#endif
}

Log::~Log()
{
#ifndef GIT_VERSION
    std::lock_guard<std::mutex> lock(Log::_log_mutex);

    std::string log_line;
    log_line = _stream.str();
    
    switch (_log_level)
    {
    case spdlog::level::level_enum::info:
        LogManager::GetLogger().info(log_line);
        if (LogManager::IsVerbose())
        {
            std::cout << "[INF]" << log_line << std::endl;
        }
        break;
    case spdlog::level::level_enum::err:
        LogManager::GetLogger().error(log_line);
        if (LogManager::IsVerbose())
        {
            std::cerr << "[ERR]" << log_line << std::endl;
        }
        break;
    case spdlog::level::level_enum::debug:
        LogManager::GetLogger().debug(log_line);
        if (LogManager::IsVerbose())
        {
            std::cout << "[DBG]" << log_line << std::endl;
        }
        break;
    case spdlog::level::level_enum::trace:
        LogManager::GetLogger().trace(log_line);
        if (LogManager::IsVerbose())
        {
            std::cout << "[TRC]" << log_line << std::endl;
        }
        break;
    case spdlog::level::level_enum::warn:
        LogManager::GetLogger().warn(log_line);
        if (LogManager::IsVerbose())
        {
            std::cout << "[WRN]" << log_line << std::endl;
        }
        break;
    case spdlog::level::level_enum::critical:
        LogManager::GetLogger().critical(log_line);
        if (LogManager::IsVerbose())
        {
            std::cerr << "[CRT]" << log_line << std::endl;
        }
        break;
    default:
        if (LogManager::IsVerbose())
        {
            std::cout << log_line << std::endl;
        }
        break;
    }
#endif
}
