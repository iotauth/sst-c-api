# plotting scripts (one point per CSV file)

These scripts treat **each CSV file as a single data point**. If a file
has multiple rows, they are averaged *within that file* first.

## Install
pip install pandas matplotlib

## Usage
Put your CSVs in a folder and do:
```bash
python throughput_plot.py path/to/folder
python latency_plot.py    path/to/folder
```

You can also mix files and folders, scan recursively, or use globs:
```bash
python throughput_plot.py results/
python throughput_plot.py results/ --recursive
python throughput_plot.py a.csv b.csv c.csv
python throughput_plot.py --glob "results/*.csv"

python latency_plot.py results/
python latency_plot.py results/ --recursive
python latency_plot.py a.csv b.csv c.csv
python latency_plot.py --glob "results/*.csv"
```

**X-axis:** "Number of Malicious Clients" (median within a file)  
**Y-axis (Throughput):** `attempt_rate_per_s` averaged within a file  
**Y-axis (Latency):** `avg_us` averaged within a file
