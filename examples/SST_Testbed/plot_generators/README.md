# Plot Script — Throughput / Latency vs. Malicious Clients

This script generates plots showing **Throughput** or **Latency** as a function of the **Number of Malicious Clients**.  
Each CSV file can contribute **up to three data points**, corresponding to:
- Row 0 → Config#2
- Row 1 → Config#3
- Row 2 → Config#1

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

Rows missing required columns are skipped.

## Output

- Outputs a PDF plot (throughput.pdf or latency.pdf)
- Never overwrites existing files (auto-incremented names)
- Produces a compact, clean figure suitable for reports

## Summary

This script aggregates experimental results from many small CSV files and visualizes how  
Config#1, Config#2, and Config#3 behave as the number of malicious clients increases.  
Ideal for reproducible experiment and benchmark analysis.