"""
generate_dataset.py — Creates PERSISTENT, FIXED CSV datasets on disk.

Run this ONCE to produce a fixed dataset. Every other script (tier1, tier2,
ml_baselines, evaluate) can then be pointed at these CSV files instead of
generating fresh random data every run — meaning results are reproducible
and identical every time, which is what a paper needs (no more "the FPR was
0.333 this run and 0.350 last run" variance from re-randomizing each time).
"""

import csv
import os
from event_log import (generate_benign_sequence, generate_sustained_attack_sequence,
                        generate_spoofed_burst, WindowEvent)

OUT_DIR = "dataset"


def write_events_csv(events: list[WindowEvent], filename: str):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, filename)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["supi", "origin", "window_index", "attempts", "failures", "timestamp", "raw_ratio"])
        for e in events:
            writer.writerow([e.supi, e.origin, e.window_index, e.attempts, e.failures,
                              e.timestamp, round(e.raw_ratio, 4)])
    print(f"wrote {len(events)} rows -> {path}")


def read_events_csv(filename: str) -> list[WindowEvent]:
    path = os.path.join(OUT_DIR, filename)
    events = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(WindowEvent(
                supi=row["supi"], origin=row["origin"],
                window_index=int(row["window_index"]),
                attempts=int(row["attempts"]), failures=int(row["failures"]),
                timestamp=float(row["timestamp"]),
            ))
    return events


if __name__ == "__main__":
    # Fixed seeds everywhere -> this dataset is now reproducible forever.

    # ML training pool: 50 synthetic benign SUPIs, 15 windows each = 750 rows
    train_events = []
    for i in range(50):
        train_events += generate_benign_sequence(f"train_{i}", "cellA", num_windows=15, seed=i)
    write_events_csv(train_events, "train_benign.csv")

    # Scenario 1: baseline benign subscriber
    write_events_csv(
        generate_benign_sequence("s1_supi", "cellA", num_windows=20, seed=11),
        "scenario1_benign.csv")

    # Scenario 2: genuine attacker, own SUPI, above 30%
    write_events_csv(
        generate_sustained_attack_sequence("s2_supi", "cellZ", num_windows=5, target_ratio=0.45),
        "scenario2_genuine_attacker.csv")

    # Scenario 3: spoofed victim, above 30%, wrong origin
    write_events_csv(
        generate_sustained_attack_sequence("s3_victim_supi", "cellZ", num_windows=3, target_ratio=0.40),
        "scenario3_spoofed_victim.csv")

    # Scenario 4: sustained sub-30% evasion attacker
    write_events_csv(
        generate_sustained_attack_sequence("s4_supi", "cellZ", num_windows=10, target_ratio=0.29),
        "scenario4_evasion.csv")

    # Held-out benign test set (separate from training pool, for fair FPR measurement)
    write_events_csv(
        generate_benign_sequence("test_benign_supi", "cellA", num_windows=30, seed=999),
        "test_benign_holdout.csv")

    print("\nAll datasets written to ./dataset/ — fixed and reproducible.")
    print("Re-running this script will overwrite with the SAME data (seeds are fixed).")
