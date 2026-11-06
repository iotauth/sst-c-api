#include "metrics.hpp"

#include <chrono>
#include <cmath>
#include <format>
#include <fstream>
#include <mutex>

namespace {
struct MetricsFile {
    std::mutex mutex;
    std::ofstream stream;
    bool header_written = false;
};

MetricsFile& metrics_file() {
    static MetricsFile file;
    return file;
}

long long epoch_us_now() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool file_exists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

std::string unused_filename(const std::string& base) {
    if (!file_exists(base)) return base;
    for (int index = 1;; ++index) {
        std::string candidate;
        if (auto dot = base.rfind('.'); dot == std::string::npos) {
            candidate = std::format("{}{}", base, index);
        } else {
            candidate = std::format("{}{}{}", base.substr(0, dot), index,
                                    base.substr(dot));
        }
        if (!file_exists(candidate)) return candidate;
    }
}
}  // namespace

void metrics_open_new_file(const std::string& base) {
    auto& file = metrics_file();
    std::scoped_lock lock(file.mutex);
    if (file.stream.is_open()) return;
    file.stream.open(unused_filename(base), std::ios::out | std::ios::app);
}

void metrics_write_header_if_empty() {
    auto& file = metrics_file();
    std::scoped_lock lock(file.mutex);
    if (!file.stream.is_open() || file.header_written) return;
    if (file.stream.tellp() == 0) {
        file.stream
            << "exp_id,malicious_number,ts_start_us,ts_end_us,successes,"
               "failures,avg_us,min_us,max_us,duration_us,"
               "attempt_rate_per_s,success_rate_per_s\n";
    }
    file.header_written = true;
}

MetricsRow metrics_begin_row(std::string_view exp_id) {
    MetricsRow row;
    row.exp_id = exp_id;
    row.ts_start_us = epoch_us_now();
    row.t0 = std::chrono::steady_clock::now();
    return row;
}

void metrics_end_row_and_write(MetricsRow& row) {
    row.ts_end_us = epoch_us_now();
    double duration_s =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - row.t0)
            .count();
    auto duration_us = std::llround(duration_s * 1e6);
    auto attempts = row.successes + row.failures;
    auto average_us = attempts ? std::llround(row.sum_us / attempts) : 0LL;
    if (row.min_us == LONG_MAX) row.min_us = 0;
    double attempt_rate = duration_s > 0 ? attempts / duration_s : 0.0;
    double success_rate = duration_s > 0 ? row.successes / duration_s : 0.0;

    auto& file = metrics_file();
    std::scoped_lock lock(file.mutex);
    if (!file.stream.is_open()) return;
    file.stream << std::format("{},{},{},{},{},{},{},{},{},{},{:.3f},{:.3f}\n",
                               row.exp_id, row.malicious_number,
                               row.ts_start_us, row.ts_end_us, row.successes,
                               row.failures, average_us, row.min_us, row.max_us,
                               duration_us, attempt_rate, success_rate);
}
