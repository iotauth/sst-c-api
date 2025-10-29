#pragma once
#include <string>
#include <cstdint>
#include <chrono>
#include <climits>

struct MetricsRow {
  std::string exp_id;
  long long ts_start_us = 0;
  long long ts_end_us = 0;

  uint64_t successes = 0, failures = 0;

  // Latency accumulators
  long double sum_us = 0.0L;
  long min_us = LONG_MAX, max_us = 0;

  // precise duration (steady clock)
  std::chrono::steady_clock::time_point t0;
};

void metrics_open_new_file(const std::string& base = "../metric_logs/client_metrics_log.csv");
void metrics_write_header_if_empty();

MetricsRow metrics_begin_row(const std::string& exp_id);

inline void metrics_add_sample(MetricsRow& r, long dur_us, bool ok) {
  r.sum_us += static_cast<long double>(dur_us);
  if (dur_us < r.min_us) r.min_us = dur_us;
  if (dur_us > r.max_us) r.max_us = dur_us;
  if (ok) ++r.successes; else ++r.failures;
}

// Writes a CSV row with:
// exp_id,ts_start,ts_end,successes,failures,avg_ms,min_ms,max_ms,attempt_qps,success_qps
void metrics_end_row_and_write(MetricsRow& r);
