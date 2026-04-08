#!/usr/bin/env python3
"""
plot.py — Plot throughput or latency vs. number of malicious clients from CSV files.

Usage:
    # Throughput mode (uses attempt_rate_per_s)
    python3 plot.py --throughput <CSV_OR_DIR> [<CSV_OR_DIR> ...]
    python3 plot.py --throughput --glob "results/*.csv"
    python3 plot.py --throughput --recursive path/to/dir

    # Latency mode (avg_us is converted to milliseconds)
    python3 plot.py --latency <CSV_OR_DIR> [<CSV_OR_DIR> ...]
    python3 plot.py --latency --glob "logs/*lat.csv"

    # Example
    python3 plot.py --throughput ../metric_logs/metric_logs_set2/syn
    python3 plot.py --latency --glob "../metric_logs/metric_logs_set2/*.csv" --logy --inset

Input format:
    - Inputs may be CSV files or directories containing CSVs.
    - You may also provide a glob pattern via --glob, and enable directory recursion via --recursive.
    - Each CSV may contain up to three rows, strictly in this order:
          row 0 -> Config#2
          row 1 -> Config#3
          row 2 -> Config#1
    - Required columns depend on mode:
          * Throughput mode: malicious_number, attempt_rate_per_s
          * Latency mode: malicious_number, avg_us
    - In latency mode, avg_us is converted to milliseconds on the y-axis.

Plot behavior:
    - The script aggregates points from all CSVs into three series: Config#2, Config#3, Config#1.
    - It plots “Number of Malicious Clients” on the x-axis against throughput (ops/s) or latency (ms).
    - Each CSV contributes up to three points—one per config, if present.
    - Both axes use integer-only ticks.
    - Y-axis uses linear scale by default; use --logy for logarithmic scale.
    - Use --inset to draw a zoomed inset focusing on lower-y regions.

Output:
    - Output is a PDF by default. You can specify a filename via --out; if no extension is given, .pdf is appended.
    - The script never overwrites existing files—names auto-increment (e.g., latency.pdf, latency1.pdf, latency2.pdf).
    - All figures are rendered in a compact form: the actual drawn area is 80% of the specified --figsize.
      You can control base size with --figsize W H.

Axis options:
    - --xlim XMIN XMAX : Clamp x-axis range.
    - --ylim YMIN YMAX : Clamp y-axis range (latency mode expects milliseconds).
    - --logy           : Enable logarithmic scaling for the y-axis.
    - --inset          : Draw a zoomed inset; useful when Config#1 dominates the scale.
    - --inset-max VAL  : Manually specify the inset’s upper y-limit (default is auto-calculated).

Summary:
    This script reads multiple CSVs and generates a compact PDF figure showing how throughput or latency
    changes as the number of malicious clients increases. CSV structure (row order and required columns)
    must match the expected format, and either --throughput or --latency must be specified.
"""
import argparse
import glob
import os
import sys
from typing import List, Dict, Optional
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter, MaxNLocator
from mpl_toolkits.axes_grid1.inset_locator import inset_axes  # For zoomed inset plotting

# Column names by mode
REQ_TPUT_COLS = ["malicious_number", "attempt_rate_per_s"]
REQ_LAT_COLS  = ["malicious_number", "avg_us"]


def expand_inputs(inputs: List[str], recursive: bool) -> List[str]:
    files: List[str] = []
    for path in inputs:
        if any(ch in path for ch in "*?[]"):
            files.extend(sorted(glob.glob(path, recursive=recursive)))
            continue
        if os.path.isdir(path):
            pattern = "**/*.csv" if recursive else "*.csv"
            search = os.path.join(path, pattern)
            files.extend(sorted(glob.glob(search, recursive=recursive)))
        elif os.path.isfile(path):
            files.append(path)
        else:
            print(f"[warn] Not found: {path}", file=sys.stderr)
    # Deduplicate while preserving order
    seen = set()
    unique_files: List[str] = []
    for f in files:
        if f not in seen:
            unique_files.append(f)
            seen.add(f)
    return unique_files


def points_from_three_rows(csv_path: str, mode: str) -> List[Dict[str, float]]:
    """
    Reads a CSV file expected to have up to three rows, each corresponding to:
    row 0 -> Config#2, row 1 -> Config#3, row 2 -> Config#1.
    Returns a list of dicts with keys: label, malicious_number, y.
    """
    labels = ["Config#2", "Config#3", "Config#1"]
    required = REQ_TPUT_COLS if mode == "throughput" else REQ_LAT_COLS
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[warn] Skipping {csv_path}: {e}", file=sys.stderr)
        return []

    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"[warn] {csv_path} missing columns: {missing}", file=sys.stderr)
        return []

    for col in required:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df_clean = df.dropna(subset=required)
    if df_clean.empty:
        print(f"[warn] {csv_path} has no numeric data after cleaning.", file=sys.stderr)
        return []

    points = []
    for i, label in enumerate(labels):
        if i >= len(df_clean):
            continue
        row = df_clean.iloc[i]
        try:
            x = float(row["malicious_number"])
            if mode == "throughput":
                y = float(row["attempt_rate_per_s"])
            else:
                y = float(row["avg_us"]) / 1000.0
            points.append({"label": label, "malicious_number": x, "y": y})
        except Exception as e:
            print(f"[warn] {csv_path} row {i} ({label}) invalid data: {e}", file=sys.stderr)
            continue
    return points


def unique_path(path: str) -> str:
    base, ext = os.path.splitext(path)
    candidate = path
    i = 1
    while os.path.exists(candidate):
        candidate = f"{base}{i}{ext}"
        i += 1
    return candidate


def ensure_pdf_suffix(path: str) -> str:
    base, ext = os.path.splitext(path)
    if ext.lower() != ".pdf":
        return base + ".pdf"
    return path


def main():
    ap = argparse.ArgumentParser(description="Plot Throughput or Latency vs Number of Malicious Clients")
    mode_group = ap.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--throughput", action="store_true", help="Plot throughput (attempt_rate_per_s)")
    mode_group.add_argument("--latency", action="store_true", help="Plot latency (avg_us → ms)")

    ap.add_argument("inputs", nargs="*", help="CSV files and/or directories")
    ap.add_argument("--glob", dest="glob_pat", help="Optional glob pattern, e.g. 'results/*.csv'")
    ap.add_argument("--recursive", action="store_true", help="Search directories recursively")
    ap.add_argument("--out", default=None, help="Output filename (PDF). Default depends on mode.")
    ap.add_argument("--figsize", nargs=2, type=float, metavar=("W","H"),
                    default=[5.5, 3.5], help="Base figure size in inches (default: 5.5 3.5). Actual image is 20% smaller.")
    ap.add_argument("--xlim", nargs=2, type=float, metavar=("XMIN","XMAX"), help="Clamp X axis to [XMIN, XMAX]")
    ap.add_argument("--ylim", nargs=2, type=float, metavar=("YMIN","YMAX"), help="Clamp Y axis to [YMIN, YMAX] (ms for latency mode)")
    # New CLI options for log scale and inset zoom
    ap.add_argument("--logy", action="store_true", help="Plot Y axis on logarithmic scale")
    ap.add_argument("--inset", action="store_true", help="Draw a zoomed inset focusing on lower-y region")
    ap.add_argument("--inset-max", type=float, default=None, help="Maximum Y value for inset zoom (default auto)")

    args = ap.parse_args()

    mode = "throughput" if args.throughput else "latency"

    paths = list(args.inputs)
    if args.glob_pat:
        paths.append(args.glob_pat)
    if not paths:
        ap.error("Provide at least one CSV or directory (or use --glob).")

    files = expand_inputs(paths, recursive=args.recursive)
    if not files:
        raise SystemExit("No CSV files found.")

    # Collect points per series label from all CSV files
    series_points = {"Config#2": [], "Config#3": [], "Config#1": []}
    for f in files:
        pts = points_from_three_rows(f, mode)
        for pt in pts:
            label = pt["label"]
            series_points[label].append(pt)

    colors = {"Config#2": "tab:blue", "Config#3": "tab:orange", "Config#1": "tab:green"}

    # Check if all series are empty
    if all(len(series_points[label]) == 0 for label in series_points):
        raise SystemExit("No usable data points from the provided CSVs.")

    # Always-compact sizing
    w, h = args.figsize
    w *= 0.8
    h *= 0.8

    plt.figure(figsize=(w, h))
    ax = plt.gca()

    # Plot each series if it has points
    all_x_values = set()
    all_y_values = []
    for label in ["Config#2", "Config#3", "Config#1"]:
        points = series_points[label]
        if not points:
            print(f"[warn] No data points for {label}", file=sys.stderr)
            continue
        df = pd.DataFrame(points).sort_values("malicious_number").reset_index(drop=True)
        plt.plot(df["malicious_number"], df["y"], marker="o", label=label, color=colors[label])
        all_x_values.update(df["malicious_number"].unique())
        all_y_values.extend(df["y"].tolist())

    ax.set_xlabel("Number of Malicious Clients", fontsize=17)

    # Set x-ticks to sorted unique malicious_number across all points
    xticks = sorted(all_x_values)
    ax.set_xticks(xticks)

    # Configure Y axis scale and formatting
    if args.logy:
        ax.set_yscale('log')
        # Do not use integer-only locator on log scale
        # Keep ylabel but skip ScalarFormatter for latency mode if logy is on
        if mode == "throughput":
            ax.set_ylabel("Throughput (ops/s)", fontsize=17)
        else:
            ax.set_ylabel("Latency (ms)", fontsize=17)
    else:
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        if mode == "throughput":
            ax.set_ylabel("Throughput (ops/s)", fontsize=17)
        else:
            ax.set_ylabel("Latency (ms)", fontsize=17)
            # Disable scientific notation for latency axis and use integer ticks
            fmt = ScalarFormatter(useMathText=False)
            fmt.set_scientific(False)
            fmt.set_useOffset(False)
            ax.yaxis.set_major_formatter(fmt)

    ax.tick_params(axis='both', which='major', labelsize=14, length=6)

    # Optional ranges
    if args.xlim:
        ax.set_xlim(args.xlim)
    if args.ylim:
        ax.set_ylim(args.ylim)

    ax.grid(True, which='major', alpha=0.3)

    # Draw zoomed inset if requested
    if args.inset:
        # Determine inset y max
        inset_ymax = args.inset_max
        if inset_ymax is None:
            # Compute max of Config#2 and Config#3 series y values
            c2_vals = [pt["y"] for pt in series_points["Config#2"]]
            c3_vals = [pt["y"] for pt in series_points["Config#3"]]
            max_c2_c3 = max(c2_vals + c3_vals) if (c2_vals or c3_vals) else None
            global_max = max(all_y_values) if all_y_values else 1.0
            if max_c2_c3 is not None:
                inset_ymax = max_c2_c3 * 1.2
            else:
                inset_ymax = global_max * 0.2

        ax_in = inset_axes(ax, width="45%", height="45%", loc="upper right", borderpad=1.0)
        # Re-plot the same series in inset
        for label in ["Config#2", "Config#3", "Config#1"]:
            points = series_points[label]
            if not points:
                continue
            df = pd.DataFrame(points).sort_values("malicious_number").reset_index(drop=True)
            ax_in.plot(df["malicious_number"], df["y"], marker="o", label=label, color=colors[label])
        ax_in.set_ylim(0, inset_ymax)
        ax_in.set_xlim(ax.get_xlim())
        ax_in.tick_params(labelsize=10)
        ax_in.grid(True, alpha=0.2)
        ax_in.set_title("zoom", fontsize=9)

    # Force legend order: Config#1 → Config#2 → Config#3
    handles, labels = ax.get_legend_handles_labels()
    desired_order = ["Config#1", "Config#2", "Config#3"]
    # keep only labels we have and sort them by desired order
    pairs = [(h, l) for h, l in zip(handles, labels) if l in desired_order]
    pairs.sort(key=lambda x: desired_order.index(x[1]))
    if pairs:
        ax.legend([h for h, _ in pairs], [l for _, l in pairs], fontsize=12)
    plt.tight_layout()

    default_out = "throughput.pdf" if mode == "throughput" else "latency.pdf"
    desired_out = ensure_pdf_suffix(args.out or default_out)
    final_out = unique_path(desired_out)
    plt.savefig(final_out, dpi=160)
    total_files_used = sum(len(series_points[label]) for label in series_points)
    print(f"[ok] Mode={mode}. Used {total_files_used} points from {len(files)} files. Wrote {final_out}")

if __name__ == "__main__":
    main()
