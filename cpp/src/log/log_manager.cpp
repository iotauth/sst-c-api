#include "log_manager.hpp"

#include <filesystem>
#include <iostream>
#include <thread>

#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

std::mutex Log::_log_mutex;
std::shared_ptr<spdlog::logger> LogManager::logger = nullptr;
bool LogManager::is_verbose = false;

void LogManager::Initialize([[maybe_unused]] const std::string& logName,
                            [[maybe_unused]] const std::string& logFilePath,
                            [[maybe_unused]] bool verbose,
                            [[maybe_unused]] std::size_t maxSizeBytes,
                            [[maybe_unused]] std::size_t maxFiles) {
#ifndef GIT_VERSION
    if (logger) {
        LOG_DBG << "Logger already initialized. Skipping re-initialization.";
        return;
    }
    // Ensure the logs directory exists
    std::filesystem::path log_dir = logFilePath;
    log_dir.remove_filename();
    if (!std::filesystem::exists(log_dir)) {
        std::filesystem::create_directories(log_dir);
    }

    // The sink rotates files itself and keeps at most maxFiles backups.
    logger = spdlog::rotating_logger_mt(logName, logFilePath, maxSizeBytes,
                                        maxFiles);
#endif
    is_verbose = verbose;
}

void LogManager::SetLogFilePath([[maybe_unused]] const std::string& logName,
                                [[maybe_unused]] const std::string& logFilePath,
                                [[maybe_unused]] std::size_t maxSizeBytes,
                                [[maybe_unused]] std::size_t maxFiles) {
#ifndef GIT_VERSION
    if (logger) {
        // Ensure the logs directory exists
        std::filesystem::path log_dir = logFilePath;
        log_dir.remove_filename();
        if (!std::filesystem::exists(log_dir)) {
            std::filesystem::create_directories(log_dir);
        }

        // spdlog refuses to register the same logger name twice. Drop the
        // existing logger before re-creating with the new path/policy.
        spdlog::drop(logName);
        logger = spdlog::rotating_logger_mt(logName, logFilePath, maxSizeBytes,
                                            maxFiles);
    }
#endif
}

spdlog::logger& LogManager::GetLogger() {
    if (!logger) {
        // Logging remains usable before explicit file logger setup.
        static std::shared_ptr<spdlog::logger> default_logger =
            spdlog::stdout_color_mt("default");
        return *default_logger;
    }
    return *logger;
}

bool LogManager::IsVerbose() { return is_verbose; }

Log::Log([[maybe_unused]] const std::string& fileName,
         [[maybe_unused]] const std::string& funcName,
         [[maybe_unused]] const long& line,
         [[maybe_unused]] spdlog::level::level_enum l) {
#ifndef GIT_VERSION
    std::thread::id tid = std::this_thread::get_id();
    std::stringstream ss_tid;
    ss_tid << tid;
    _log_level = l;

    _stream << " [" << fileName << "::" << funcName << "(" << line
            << ")] (thxid: " << ss_tid.str() << ") - ";
#endif
}

Log::~Log() {
#ifndef GIT_VERSION
    // Destructors are implicitly noexcept: an exception escaping here would
    // terminate the program, so logging failures are swallowed instead.
    try {
        std::lock_guard<std::mutex> lock(Log::_log_mutex);

        std::string log_line;
        log_line = _stream.str();

        switch (_log_level) {
            case spdlog::level::level_enum::info:
                LogManager::GetLogger().info(log_line);
                if (LogManager::IsVerbose()) {
                    std::cout << "[INF]" << log_line << std::endl;
                }
                break;
            case spdlog::level::level_enum::err:
                LogManager::GetLogger().error(log_line);
                if (LogManager::IsVerbose()) {
                    std::cerr << "[ERR]" << log_line << std::endl;
                }
                break;
            case spdlog::level::level_enum::debug:
                LogManager::GetLogger().debug(log_line);
                if (LogManager::IsVerbose()) {
                    std::cout << "[DBG]" << log_line << std::endl;
                }
                break;
            case spdlog::level::level_enum::trace:
                LogManager::GetLogger().trace(log_line);
                if (LogManager::IsVerbose()) {
                    std::cout << "[TRC]" << log_line << std::endl;
                }
                break;
            case spdlog::level::level_enum::warn:
                LogManager::GetLogger().warn(log_line);
                if (LogManager::IsVerbose()) {
                    std::cout << "[WRN]" << log_line << std::endl;
                }
                break;
            case spdlog::level::level_enum::critical:
                LogManager::GetLogger().critical(log_line);
                if (LogManager::IsVerbose()) {
                    std::cerr << "[CRT]" << log_line << std::endl;
                }
                break;
            default:
                if (LogManager::IsVerbose()) {
                    std::cout << log_line << std::endl;
                }
                break;
        }
    } catch (...) {
        // Nothing safe to do if logging itself fails; drop the log line.
    }
#endif
}
