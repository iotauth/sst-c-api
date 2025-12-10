
#!/usr/bin/env python3
"""
throughput_plot.py
Plot Throughput (attempt_rate_per_s) vs Number of Malicious Clients where
each CSV file contributes exactly one point.

- Outputs a PDF by default; won't overwrite existing files (auto-increments).
- Always renders in a compact form (20% smaller). Use --figsize W H to control base size.
- Integer-only ticks on both axes.
- Optional --xlim/--ylim to clamp axis ranges.
"""
import argparse
import glob
import os
import sys
from typing import List
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

REQUIRED_COLS = ["malicious_number", "attempt_rate_per_s"]

def expand_inputs(inputs: List[str], recursive: bool) -> List[str]:
    files = []
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
    unique_files = []
    for f in files:
        if f not in seen:
            unique_files.append(f)
            seen.add(f)
    return unique_files

def point_from_file(csv_path: str):
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[warn] Skipping {csv_path}: {e}", file=sys.stderr)
        return None
    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        print(f"[warn] {csv_path} missing columns: {missing}", file=sys.stderr)
        return None
    for col in REQUIRED_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df_clean = df.dropna(subset=REQUIRED_COLS)
    if df_clean.empty:
        print(f"[warn] {csv_path} has no numeric data after cleaning.", file=sys.stderr)
        return None
    x = float(df_clean["malicious_number"].median())
    y = float(df_clean["attempt_rate_per_s"].mean())
    return {"source": csv_path, "malicious_number": x, "throughput": y}

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
    ap = argparse.ArgumentParser(description="Plot Throughput vs Number of Malicious Clients")
    ap.add_argument("inputs", nargs="*", help="CSV files and/or directories")
    ap.add_argument("--glob", dest="glob_pat", help="Optional glob pattern, e.g. 'results/*.csv'")
    ap.add_argument("--recursive", action="store_true", help="Search directories recursively")
    ap.add_argument("--out", default="throughput.pdf", help="Output filename (PDF). Default: throughput.pdf")
    ap.add_argument("--figsize", nargs=2, type=float, metavar=("W","H"),
                    default=[5.5, 3.5], help="Base figure size in inches (default: 5.5 3.5). Actual image is 20% smaller.")
    ap.add_argument("--xlim", nargs=2, type=float, metavar=("XMIN","XMAX"), help="Clamp X axis to [XMIN, XMAX]")
    ap.add_argument("--ylim", nargs=2, type=float, metavar=("YMIN","YMAX"), help="Clamp Y axis to [YMIN, YMAX]")
    args = ap.parse_args()

    paths = list(args.inputs)
    if args.glob_pat:
        paths.append(args.glob_pat)
    if not paths:
        ap.error("Provide at least one CSV or directory (or use --glob).")

    files = expand_inputs(paths, recursive=args.recursive)
    if not files:
        raise SystemExit("No CSV files found.")

    points = []
    for f in files:
        pt = point_from_file(f)
        if pt is not None:
            points.append(pt)
    if not points:
        raise SystemExit("No usable data points from the provided CSVs.")

    df = pd.DataFrame(points).sort_values("malicious_number").reset_index(drop=True)

    # Always-compact sizing
    w, h = args.figsize
    w *= 0.8
    h *= 0.8

    # Plot
    plt.figure(figsize=(w, h))
    plt.plot(df["malicious_number"], df["throughput"], marker="o")
    ax = plt.gca()
    ax.set_xlabel("Number of Malicious Clients", fontsize=18)
    ax.set_ylabel("Throughput (attempts/s)", fontsize=18)
    ax.tick_params(axis='both', which='major', labelsize=14, length=6)
    # Integer-only ticks
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    # Optional ranges
    if args.xlim: ax.set_xlim(args.xlim)
    if args.ylim: ax.set_ylim(args.ylim)
    ax.grid(True, which='major', alpha=0.3)
    plt.tight_layout()

    desired_out = ensure_pdf_suffix(args.out)
    final_out = unique_path(desired_out)
    plt.savefig(final_out, dpi=160)
    print(f"[ok] Used {len(df)} files. Wrote {final_out}")

if __name__ == "__main__":
    main()
