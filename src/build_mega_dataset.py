#!/usr/bin/env python3
"""
Build a ~300,000-row mega dataset from all 63 CIC-IoT2023 Merged CSV files.
Samples evenly across files for maximum attack-type diversity.
Output: datasets/cic_iot2023_full.csv
"""
import csv
import os
import random
import sys
import time
from collections import Counter

TARGET_ROWS = 300_000
MERGED_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets", "MERGED_CSV")
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "datasets", "cic_iot2023_full.csv")

def main():
    files = sorted(
        f for f in os.listdir(MERGED_DIR)
        if f.startswith("Merged") and f.endswith(".csv")
    )
    print(f"[*] Found {len(files)} Merged CSV files")
    
    rows_per_file = TARGET_ROWS // len(files)  # ~4,762 per file
    extra = TARGET_ROWS % len(files)
    
    print(f"[*] Sampling ~{rows_per_file} rows per file (target: {TARGET_ROWS:,} total)")
    print(f"[*] Output: {OUTPUT}")
    print()
    
    header = None
    all_rows = []
    label_counts = Counter()
    
    for i, fn in enumerate(files, 1):
        path = os.path.join(MERGED_DIR, fn)
        file_rows = []
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            file_header = next(reader)
            
            if header is None:
                header = file_header
            
            # Read all rows into memory for this file, then sample
            for row in reader:
                if len(row) == len(header):
                    file_rows.append(row)
        
        # Sample from this file
        take = rows_per_file + (1 if i <= extra else 0)
        if len(file_rows) <= take:
            sampled = file_rows
        else:
            sampled = random.sample(file_rows, take)
        
        # Count labels (last column)
        for row in sampled:
            label_counts[row[-1]] += 1
        
        all_rows.extend(sampled)
        elapsed_pct = (i / len(files)) * 100
        print(f"  [{i:2d}/{len(files)}] {fn}: read {len(file_rows):,} rows, sampled {len(sampled):,}  ({elapsed_pct:.0f}%)")
    
    # Shuffle for good measure
    random.shuffle(all_rows)
    
    # Write output
    print(f"\n[*] Writing {len(all_rows):,} rows to {OUTPUT}...")
    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(all_rows)
    
    size_mb = os.path.getsize(OUTPUT) / (1024 * 1024)
    print(f"[+] Done! {len(all_rows):,} rows, {size_mb:.1f} MB")
    print()
    print("[*] Label distribution:")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = (count / len(all_rows)) * 100
        print(f"    {label:35s}: {count:>8,} ({pct:5.1f}%)")
    
    return 0


if __name__ == "__main__":
    random.seed(42)  # reproducible
    t0 = time.time()
    rc = main()
    print(f"\n[*] Elapsed: {time.time()-t0:.1f}s")
    sys.exit(rc)
