# Plot Script — Throughput / Latency vs. Malicious Clients

This script generates plots showing **Throughput** or **Latency** as a function of the **Number of Malicious Clients**.

It supports two input modes:
- **Prepared CSV mode**: each CSV file can contribute **up to three data points**, corresponding to:
- Row 0 → Config#1
- Row 1 → Config#2
- Row 2 → Config#3
- **Raw metrics mode**: provide the raw metrics logs for each configuration separately with `--config1`, `--config2`, and `--config3`.

In throughput mode, the script reads `attempt_rate_per_s`.  
In latency mode, it converts `avg_us` to milliseconds.

## Usage

Throughput:
```
python3 plot.py --throughput path/to/csvs_or_dirs
```

Latency:
```
python3 plot.py --latency path/to/csvs_or_dirs
```

Raw metrics:
```
python3 plot.py --throughput --config1 path/to/config1_logs --config2 path/to/config2_logs --config3 path/to/config3_logs
python3 plot.py --latency --config1 "logs/c1/*.csv" --config2 "logs/c2/*.csv" --config3 "logs/c3/*.csv"
```

You may pass:
- Individual CSV files
- Directories containing CSVs
- Glob patterns (e.g., --glob "results/*.csv")
- Recursive scanning (--recursive)

Example:
```
python3 plot.py --throughput ../metric_logs/metric_logs_set2/syn
```

## CSV Requirements

Required columns:
- malicious_number
- attempt_rate_per_s (throughput mode)
- avg_us (latency mode; converted to ms)

In raw metrics mode, the script averages all rows/files for the same `malicious_number` within each config.
Rows missing required columns are skipped.

## Output

- Outputs a PDF plot (throughput.pdf or latency.pdf)
- Never overwrites existing files (auto-incremented names)
- Produces a compact, clean figure suitable for reports

## Summary

This script aggregates experimental results and visualizes how
Config#1, Config#2, and Config#3 behave as the number of malicious clients increases.
It can plot either prepared 3-row CSV summaries or raw metrics logs directly.
