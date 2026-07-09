#!/usr/bin/env python3
"""Engineer rolling features for NWDAF threshold-sweep CSV data.

This script reads a sweep CSV, sorts rows by (imsi, window_index/timestamp),
computes the rolling features described for Phase 2.2, and writes an
augmented CSV with the extra columns. Phase 2.3 adds an IMSI-level train/test
split so correlated rows from the same campaign stay together.
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

try:
    from sklearn.model_selection import train_test_split
except ImportError:  # pragma: no cover - exercised only in minimal environments
    train_test_split = None


def parse_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def sort_key(row: dict[str, str]) -> tuple[object, ...]:
    imsi = row.get("imsi", "")
    window_index_raw = row.get("window_index", "")
    ts = parse_float(row.get("timestamp_unix", "0"))
    if window_index_raw in {"", None}:
        return (imsi, 1, 0, ts)
    try:
        window_index = int(window_index_raw)
    except ValueError:
        window_index = 10**9
    return (imsi, 0, window_index, ts)


def build_campaign_split_map(
    rows: list[dict[str, str]],
    test_size: float = 0.3,
    random_state: int = 42,
) -> dict[tuple[str, str], str]:
    campaign_keys = list(
        dict.fromkeys((row.get("imsi", ""), row.get("attack_type", "")) for row in rows)
    )
    if not campaign_keys:
        return {}

    if len(campaign_keys) < 2:
        return {campaign_keys[0]: "train"}

    if train_test_split is None:
        raise ImportError("scikit-learn is required for IMSI-level train/test splitting")

    attack_types = [campaign[1] or "unknown" for campaign in campaign_keys]

    try:
        train_campaigns, test_campaigns = train_test_split(
            campaign_keys,
            test_size=test_size,
            random_state=random_state,
            stratify=attack_types,
        )
    except ValueError:
        train_campaigns, test_campaigns = train_test_split(
            campaign_keys,
            test_size=test_size,
            random_state=random_state,
        )

    split_map: dict[tuple[str, str], str] = {}
    for campaign in train_campaigns:
        split_map[campaign] = "train"
    for campaign in test_campaigns:
        split_map[campaign] = "test"
    return split_map


def engineer_features(
    input_path: Path,
    output_path: Path,
    lookback: int = 5,
    test_size: float = 0.3,
    random_state: int = 42,
) -> int:
    with input_path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))

    split_map = build_campaign_split_map(rows, test_size=test_size, random_state=random_state)

    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row.get("imsi", "")].append(row)

    ordered_rows: list[dict[str, str]] = []
    for imsi in sorted(grouped):
        grouped_rows = grouped[imsi]
        grouped_rows = sorted(grouped_rows, key=sort_key)
        history: list[float] = []
        for row in grouped_rows:
            campaign_key = (row.get("imsi", ""), row.get("attack_type", ""))
            row["data_split"] = split_map.get(campaign_key, "train")

            ratio = parse_float(row.get("failure_ratio", "0"))
            history.append(ratio)
            window = history[-min(lookback, len(history)) :]
            rolling_mean = sum(window) / len(window)
            rolling_max = max(window)
            windows_above_soft_thresh = sum(1 for x in window if x > 0.20)
            if len(history) <= 1:
                ratio_slope = 0.0
            else:
                window_len = min(lookback, len(history))
                start_idx = len(history) - window_len
                start_ratio = history[start_idx]
                steps = window_len - 1
                ratio_slope = (ratio - start_ratio) / steps if steps > 0 else 0.0

            row["rolling_mean_ratio"] = f"{rolling_mean:.6f}"
            row["rolling_max_ratio"] = f"{rolling_max:.6f}"
            row["windows_above_soft_thresh"] = str(windows_above_soft_thresh)
            row["ratio_slope"] = f"{ratio_slope:.6f}"
            ordered_rows.append(row)

    ordered_rows.sort(key=lambda row: (row.get("imsi", ""), sort_key(row)))

    with output_path.open("w", encoding="utf-8", newline="") as fh:
        fieldnames = list(rows[0].keys()) if rows else []
        for extra in [
            "rolling_mean_ratio",
            "rolling_max_ratio",
            "windows_above_soft_thresh",
            "ratio_slope",
            "data_split",
        ]:
            if extra not in fieldnames:
                fieldnames.append(extra)
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ordered_rows)

    return len(ordered_rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lookback", type=int, default=5)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = engineer_features(
        input_path,
        output_path,
        args.lookback,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    print(f"wrote {count} rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
