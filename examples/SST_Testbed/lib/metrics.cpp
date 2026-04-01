#include "metrics.hpp"

#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <cstdlib>

using namespace std;

static mutex g_mu;
static ofstream g_f;
static bool g_open = false, g_header = false;

#include <chrono>
#include <cstdint>

static inline long long epoch_us_now() {
    using namespace std::chrono;
    return duration_cast<microseconds>(system_clock::now().time_since_epoch())
        .count();
}

static long long malicious_number_from_env() {
    const char* raw = std::getenv("SST_MALICIOUS_CLIENTS");
    if (!raw || !*raw) return 0;
    char* end = nullptr;
    long long value = std::strtoll(raw, &end, 10);
    if (end == raw || (end && *end != '\0') || value < 0) return 0;
    return value;
}

static std::string with_malicious_number_suffix(const std::string& base) {
    long long malicious_number = malicious_number_from_env();
    if (malicious_number <= 0) return base;

    auto slash = base.find_last_of("/\\");
    std::string dir = (slash == std::string::npos) ? "" : base.substr(0, slash + 1);
    std::string file = (slash == std::string::npos) ? base : base.substr(slash + 1);
    auto dot = file.rfind('.');
    if (dot == std::string::npos) {
        return dir + file + "_mc" + std::to_string(malicious_number);
    }
    return dir + file.substr(0, dot) + "_mc" + std::to_string(malicious_number) +
           file.substr(dot);
}

// helper function for metrics_open_new_file()
static bool file_exists(const std::string& path) {
    std::ifstream p(path);
    return p.good();
}

void metrics_open_new_file(const std::string& base) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_open) return;

    std::string name = with_malicious_number_suffix(base);
    if (file_exists(name)) {
        for (int i = 1;; ++i) {
            std::string cand = name;
            auto dot = cand.rfind('.');
            if (dot == std::string::npos) {
                cand += std::to_string(i);
            } else {
                cand =
                    cand.substr(0, dot) + std::to_string(i) + cand.substr(dot);
            }
            if (!file_exists(cand)) {
                name = cand;
                break;
            }
        }
    }
    g_f.open(name, std::ios::out | std::ios::app);
    g_open = static_cast<bool>(g_f);
}

void metrics_write_header_if_empty() {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_open || g_header) return;
    if (g_f.tellp() == 0) {
        g_f << "exp_id,malicious_number,ts_start_us,ts_end_us,successes,failures,"
               "avg_us,min_us,max_us,duration_us,attempt_rate_per_s,success_"
               "rate_per_s\n";
    }
    g_header = true;
}

MetricsRow metrics_begin_row(const std::string& exp_id) {
    MetricsRow r;
    r.exp_id = exp_id;
    r.malicious_number = malicious_number_from_env();
    r.ts_start_us = epoch_us_now();
    r.t0 = std::chrono::steady_clock::now();
    return r;
}

void metrics_end_row_and_write(MetricsRow& r) {
    using namespace std::chrono;

    r.ts_end_us = epoch_us_now();
    auto t1 = steady_clock::now();
    double duration_s = duration_cast<duration<double> >(t1 - r.t0).count();
    long long duration_us_ll =
        static_cast<long long>(std::llround(duration_s * 1e6));

    long attempts = static_cast<long>(r.successes + r.failures);
    long long avg_us_ll =
        attempts ? static_cast<long long>(std::llround(r.sum_us / attempts))
                 : 0;
    if (r.min_us == LONG_MAX) r.min_us = 0;  // handle empty

    double attempt_rate =
        duration_s > 0 ? static_cast<double>(attempts) / duration_s : 0.0;
    double success_rate =
        duration_s > 0 ? static_cast<double>(r.successes) / duration_s : 0.0;

    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_open) return;
    g_f << r.exp_id << ',' << r.malicious_number << ',' << r.ts_start_us << ','
        << r.ts_end_us << ',' << r.successes << ',' << r.failures << ',' << avg_us_ll << ','
        << static_cast<long long>(r.min_us) << ','
        << static_cast<long long>(r.max_us) << ',' << duration_us_ll << ','
        << std::fixed << std::setprecision(3) << attempt_rate << ','
        << success_rate << '\n';
}
