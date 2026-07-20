"""Generate a larger labelled dataset and train the requested anomaly models."""

from __future__ import annotations

import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "experiments"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def build_dataset() -> list[dict[str, Any]]:
    rng = random.Random(7)
    rows: list[dict[str, Any]] = []

    # Benign traffic: 15 IMSIs x 8 windows = 120 windows.
    for imsi_idx in range(15):
        imsi = f"imsi-{imsi_idx + 1:03d}"
        base_time = 1_700_000_000 + imsi_idx * 100_000
        for window_index in range(8):
            attempts = rng.randint(1, 3)
            failure_prob = 0.02 + 0.01 * (imsi_idx % 4)
            failures = sum(1 for _ in range(attempts) if rng.random() < failure_prob)
            row = {
                "timestamp_unix": base_time + window_index * 30,
                "imsi": imsi,
                "attack_type": "benign",
                "is_attack": False,
                "auth_attempts": attempts,
                "auth_failures": failures,
                "failure_ratio": round(failures / attempts if attempts else 0.0, 6),
                "window_index": window_index,
            }
            rows.append(row)

    # Naive burst attacks: 4 IMSIs x 8 windows = 32 windows.
    for imsi_idx in range(4):
        imsi = f"imsi-attack-naive-{imsi_idx + 1:02d}"
        base_time = 1_700_010_000 + imsi_idx * 100_000
        for window_index in range(8):
            attempts = 100
            failures = 35 + (imsi_idx % 3) * 2
            row = {
                "timestamp_unix": base_time + window_index * 30,
                "imsi": imsi,
                "attack_type": "naive_burst",
                "is_attack": True,
                "auth_attempts": attempts,
                "auth_failures": failures,
                "failure_ratio": round(failures / attempts, 6),
                "window_index": window_index,
            }
            rows.append(row)

    # Paced evasion attacks: 4 IMSIs x 8 windows = 32 windows.
    ratios = [0.12, 0.14, 0.16, 0.18, 0.20, 0.23, 0.25, 0.29]
    for imsi_idx in range(4):
        imsi = f"imsi-attack-paced-{imsi_idx + 1:02d}"
        base_time = 1_700_020_000 + imsi_idx * 100_000
        for window_index, ratio in enumerate(ratios):
            attempts = 100
            failures = int(round(attempts * ratio))
            row = {
                "timestamp_unix": base_time + window_index * 30,
                "imsi": imsi,
                "attack_type": "paced_evasion",
                "is_attack": True,
                "auth_attempts": attempts,
                "auth_failures": failures,
                "failure_ratio": round(failures / attempts, 6),
                "window_index": window_index,
            }
            rows.append(row)

    # Optional edge-case rows: benign but high-failure due to temporary radio issues.
    for imsi_idx in range(3):
        imsi = f"imsi-edge-{imsi_idx + 1:02d}"
        base_time = 1_700_030_000 + imsi_idx * 100_000
        for window_index in range(4):
            attempts = rng.randint(2, 4)
            failures = attempts - 1
            row = {
                "timestamp_unix": base_time + window_index * 30,
                "imsi": imsi,
                "attack_type": "benign_edge_case",
                "is_attack": False,
                "auth_attempts": attempts,
                "auth_failures": failures,
                "failure_ratio": round(failures / attempts, 6),
                "window_index": window_index,
            }
            rows.append(row)

    return rows


def add_roll_features(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows_by_imsi: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_imsi[row["imsi"]].append(row)

    for imsi_rows in rows_by_imsi.values():
        imsi_rows.sort(key=lambda row: (row["timestamp_unix"], row["window_index"]))
        history: list[float] = []
        for row in imsi_rows:
            ratio = row["failure_ratio"]
            if history:
                rolling_mean = float(np.mean(history[-3:]))
                rolling_max = float(np.max(history[-3:]))
                windows_above_soft_thresh = sum(1 for x in history[-3:] if x >= 0.15)
                ratio_slope = ratio - history[-1]
            else:
                rolling_mean = 0.0
                rolling_max = 0.0
                windows_above_soft_thresh = 0
                ratio_slope = 0.0
            row["rolling_mean_ratio"] = round(rolling_mean, 6)
            row["rolling_max_ratio"] = round(rolling_max, 6)
            row["windows_above_soft_thresh"] = windows_above_soft_thresh
            row["ratio_slope"] = round(ratio_slope, 6)
            history.append(ratio)

    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    fieldnames = [
        "timestamp_unix",
        "imsi",
        "attack_type",
        "is_attack",
        "auth_attempts",
        "auth_failures",
        "failure_ratio",
        "window_index",
        "rolling_mean_ratio",
        "rolling_max_ratio",
        "windows_above_soft_thresh",
        "ratio_slope",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def load_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def build_feature_vector(row: dict[str, Any], include_roll_features: bool) -> list[float]:
    features = [float(row["auth_attempts"]), float(row["auth_failures"]), float(row["failure_ratio"])]
    if include_roll_features:
        features.extend([
            float(row["rolling_mean_ratio"]),
            float(row["rolling_max_ratio"]),
            float(row["windows_above_soft_thresh"]),
            float(row["ratio_slope"]),
        ])
    return features


def fit_and_score(rows: list[dict[str, Any]], include_roll_features: bool, contamination: float):
    benign_rows = [row for row in rows if not row["is_attack"] and row["attack_type"] == "benign"]
    attack_rows = [row for row in rows if row["is_attack"] and row["attack_type"] in {"naive_burst", "paced_evasion"}]

    train_imsi = {row["imsi"] for row in benign_rows if int(row["imsi"].split("-")[-1]) <= 10}
    test_benign_rows = [row for row in benign_rows if row["imsi"] not in train_imsi]
    test_attack_rows = [row for row in attack_rows if row["imsi"] not in train_imsi]

    train_rows = [row for row in benign_rows if row["imsi"] in train_imsi]
    test_rows = test_benign_rows + test_attack_rows

    X_train = np.array([build_feature_vector(row, include_roll_features) for row in train_rows], dtype=float)
    X_test = np.array([build_feature_vector(row, include_roll_features) for row in test_rows], dtype=float)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(X_train_scaled)
    train_scores = model.score_samples(X_train_scaled)
    test_scores = model.score_samples(X_test_scaled)
    threshold = float(np.percentile(train_scores, contamination * 100))
    preds = test_scores < threshold

    benign_fp = float(np.mean([p for p, row in zip(preds, test_rows) if not row["is_attack"]])) if any(not row["is_attack"] for row in test_rows) else 0.0
    naive_rows = [row for row in test_rows if row["attack_type"] == "naive_burst"]
    paced_rows = [row for row in test_rows if row["attack_type"] == "paced_evasion"]
    naive_detection = float(np.mean([p for p, row in zip(preds, test_rows) if row["attack_type"] == "naive_burst"])) if naive_rows else 0.0
    paced_detection = float(np.mean([p for p, row in zip(preds, test_rows) if row["attack_type"] == "paced_evasion"])) if paced_rows else 0.0

    per_imsi_results = []
    grouped_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in test_attack_rows:
        grouped_rows[row["imsi"]].append(row)
    for imsi, attack_group in grouped_rows.items():
        attack_indices = [idx for idx, row in enumerate(test_rows) if row["imsi"] == imsi]
        flagged = sum(1 for idx in attack_indices if preds[idx])
        per_imsi_results.append({"imsi": imsi, "flagged_windows": flagged, "total_windows": len(attack_group), "detection_rate": flagged / len(attack_group)})

    return {
        "contamination": contamination,
        "benign_false_positive_rate": benign_fp,
        "naive_attack_detection_rate": naive_detection,
        "paced_evasion_detection_rate": paced_detection,
        "per_imsi_detection_rate": float(np.mean([item["detection_rate"] for item in per_imsi_results])) if per_imsi_results else 0.0,
        "per_imsi_results": per_imsi_results,
        "predictions": [
            {
                "imsi": row["imsi"],
                "attack_type": row["attack_type"],
                "is_attack": row["is_attack"],
                "prediction": bool(pred),
                "timestamp_unix": row["timestamp_unix"],
                "window_index": row["window_index"],
            }
            for pred, row in zip(preds, test_rows)
        ],
    }


def write_predictions(path: Path, predictions: list[dict[str, Any]]) -> None:
    fieldnames = ["imsi", "attack_type", "is_attack", "prediction", "timestamp_unix", "window_index"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in predictions:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)


def build_svg(summary: dict[str, Any], output_path: Path) -> None:
    metrics = [
        ("Benign FPR", summary["model_a"]["benign_false_positive_rate"]),
        ("Naive detection", summary["model_a"]["naive_attack_detection_rate"]),
        ("Paced detection", summary["model_a"]["paced_evasion_detection_rate"]),
    ]
    model_b_metrics = [
        ("Benign FPR", summary["model_b"]["benign_false_positive_rate"]),
        ("Naive detection", summary["model_b"]["naive_attack_detection_rate"]),
        ("Paced detection", summary["model_b"]["paced_evasion_detection_rate"]),
    ]
    width = 800
    height = 400
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">']
    svg.append('<rect width="100%" height="100%" fill="white"/>')
    svg.append('<text x="20" y="30" font-size="18">Phase 2 model comparison</text>')
    for index, ((label, value), (label_b, value_b)) in enumerate(zip(metrics, model_b_metrics)):
        x = 120 + index * 220
        bar_a = 300 - int(value * 240)
        bar_b = 300 - int(value_b * 240)
        svg.append(f'<rect x="{x}" y="{bar_a}" width="50" height="{300 - bar_a}" fill="#4c78a8"/>')
        svg.append(f'<rect x="{x + 60}" y="{bar_b}" width="50" height="{300 - bar_b}" fill="#f58518"/>')
        svg.append(f'<text x="{x - 10}" y="330" font-size="12">{label}</text>')
        svg.append(f'<text x="{x}" y="{bar_a - 5}" font-size="10">A {value:.2f}</text>')
        svg.append(f'<text x="{x + 60}" y="{bar_b - 5}" font-size="10">B {value_b:.2f}</text>')
    svg.append('</svg>')
    output_path.write_text("\n".join(svg), encoding="utf-8")


def main() -> None:
    raw_rows = build_dataset()
    rows = add_roll_features(raw_rows)
    features_path = OUT_DIR / "phase2_2_features.csv"
    write_csv(rows, features_path)

    model_a_results = []
    model_b_results = []
    for contamination in [0.01, 0.03, 0.05, 0.10]:
        model_a_results.append(fit_and_score(rows, include_roll_features=False, contamination=contamination))
        model_b_results.append(fit_and_score(rows, include_roll_features=True, contamination=contamination))

    def choose_best(summary_results: list[dict[str, Any]]) -> dict[str, Any]:
        best = None
        best_score = None
        for item in summary_results:
            score = (item["naive_attack_detection_rate"] + item["paced_evasion_detection_rate"]) / 2.0 - item["benign_false_positive_rate"]
            if best_score is None or score > best_score:
                best_score = score
                best = item
        return best

    model_a_best = choose_best(model_a_results)
    model_b_best = choose_best(model_b_results)
    model_a_predictions = model_a_best["predictions"]
    model_b_predictions = model_b_best["predictions"]

    summary = {
        "dataset_rows": len(rows),
        "benign_windows": sum(1 for row in rows if row["attack_type"] == "benign"),
        "naive_attack_windows": sum(1 for row in rows if row["attack_type"] == "naive_burst"),
        "paced_evasion_windows": sum(1 for row in rows if row["attack_type"] == "paced_evasion"),
        "model_a": {
            "selected_contamination": model_a_best["contamination"],
            "benign_false_positive_rate": model_a_best["benign_false_positive_rate"],
            "naive_attack_detection_rate": model_a_best["naive_attack_detection_rate"],
            "paced_evasion_detection_rate": model_a_best["paced_evasion_detection_rate"],
            "per_imsi_detection_rate": model_a_best["per_imsi_detection_rate"],
            "per_imsi_results": model_a_best["per_imsi_results"],
            "sweep": [{
                "contamination": item["contamination"],
                "benign_false_positive_rate": item["benign_false_positive_rate"],
                "naive_attack_detection_rate": item["naive_attack_detection_rate"],
                "paced_evasion_detection_rate": item["paced_evasion_detection_rate"],
            } for item in model_a_results],
        },
        "model_b": {
            "selected_contamination": model_b_best["contamination"],
            "benign_false_positive_rate": model_b_best["benign_false_positive_rate"],
            "naive_attack_detection_rate": model_b_best["naive_attack_detection_rate"],
            "paced_evasion_detection_rate": model_b_best["paced_evasion_detection_rate"],
            "per_imsi_detection_rate": model_b_best["per_imsi_detection_rate"],
            "per_imsi_results": model_b_best["per_imsi_results"],
            "sweep": [{
                "contamination": item["contamination"],
                "benign_false_positive_rate": item["benign_false_positive_rate"],
                "naive_attack_detection_rate": item["naive_attack_detection_rate"],
                "paced_evasion_detection_rate": item["paced_evasion_detection_rate"],
            } for item in model_b_results],
        },
        "model_comparison": {
            "improvement_in_paced_detection": model_b_best["paced_evasion_detection_rate"] - model_a_best["paced_evasion_detection_rate"],
            "improvement_in_naive_detection": model_b_best["naive_attack_detection_rate"] - model_a_best["naive_attack_detection_rate"],
            "change_in_benign_fpr": model_b_best["benign_false_positive_rate"] - model_a_best["benign_false_positive_rate"],
        },
    }

    write_predictions(OUT_DIR / "model_a_predictions.csv", model_a_predictions)
    write_predictions(OUT_DIR / "model_b_predictions.csv", model_b_predictions)
    write_summary(OUT_DIR / "evaluation_summary.json", summary)
    build_svg(summary, OUT_DIR / "phase2_model_comparison.svg")

    print(f"Wrote {features_path}")
    print(f"Wrote {OUT_DIR / 'model_a_predictions.csv'}")
    print(f"Wrote {OUT_DIR / 'model_b_predictions.csv'}")
    print(f"Wrote {OUT_DIR / 'evaluation_summary.json'}")
    print(f"Wrote {OUT_DIR / 'phase2_model_comparison.svg'}")


if __name__ == "__main__":
    main()
