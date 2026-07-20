#!/usr/bin/env python3
"""Phase 2.4: train and evaluate benign-only Isolation Forest detectors.

The input is the extended threshold-sweep data produced in Phase 2.1.  This
script re-creates the Phase 2.2 rolling features, then makes an IMSI-grouped,
stratified holdout split (Phase 2.3) before fitting two Isolation Forests:

* Model A: instantaneous authentication counters and failure ratio.
* Model B: Model A plus rolling, temporal features.

Attack labels are used only to select benign training rows and to report the
holdout results; they are never passed to either Isolation Forest's ``fit``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import StratifiedGroupKFold


BASE_FEATURES = ["auth_attempts", "auth_failures", "failure_ratio"]
ROLLING_FEATURES = [
    "rolling_mean_ratio",
    "rolling_max_ratio",
    "windows_above_soft_thresh",
    "ratio_slope",
]
MODEL_FEATURES = {
    "model_a": BASE_FEATURES,
    "model_b": BASE_FEATURES + ROLLING_FEATURES,
}


def add_rolling_features(frame: pd.DataFrame, window: int, soft_threshold: float) -> pd.DataFrame:
    """Return time-ordered per-IMSI windows with Phase 2.2 features.

    Every feature only uses the current and prior rows for the same IMSI;
    there is no look-ahead into later windows.  The first row of each IMSI
    gets a slope of zero, which makes short benign sequences valid inputs.
    """
    data = frame.copy()
    data["timestamp_unix"] = pd.to_numeric(data["timestamp_unix"], errors="raise")
    data["failure_ratio"] = pd.to_numeric(data["failure_ratio"], errors="raise")
    data = data.sort_values(["imsi", "timestamp_unix"], kind="stable").reset_index(drop=True)

    grouped = data.groupby("imsi", group_keys=False)["failure_ratio"]
    data["rolling_mean_ratio"] = grouped.transform(
        lambda values: values.rolling(window=window, min_periods=1).mean()
    )
    data["rolling_max_ratio"] = grouped.transform(
        lambda values: values.rolling(window=window, min_periods=1).max()
    )
    data["windows_above_soft_thresh"] = grouped.transform(
        lambda values: values.gt(soft_threshold).rolling(window=window, min_periods=1).sum()
    )
    data["ratio_slope"] = grouped.transform(lambda values: values.diff().fillna(0.0))
    return data


def grouped_stratified_split(data: pd.DataFrame, test_size_folds: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split complete IMSIs into stratified train/test partitions.

    A group is never present on both sides, preventing a detector from seeing
    earlier windows from a target IMSI while being evaluated on later ones.
    """
    if data["imsi"].nunique() < test_size_folds:
        raise ValueError("Need at least as many IMSIs as split folds.")
    labels = data["attack_type"].astype(str)
    splitter = StratifiedGroupKFold(n_splits=test_size_folds, shuffle=True, random_state=42)
    train_idx, test_idx = next(splitter.split(data, labels, groups=data["imsi"]))
    return data.iloc[train_idx].copy(), data.iloc[test_idx].copy()


def evaluate(model: IsolationForest, features: list[str], test: pd.DataFrame) -> pd.DataFrame:
    """Attach Isolation Forest outputs to a holdout frame."""
    results = test.copy()
    # sklearn uses -1 for anomaly and +1 for inlier.
    results["prediction"] = model.predict(results[features])
    results["detected"] = results["prediction"].eq(-1)
    results["anomaly_score"] = model.decision_function(results[features])
    return results


def summary(results: pd.DataFrame) -> dict[str, object]:
    by_attack = (
        results.groupby("attack_type", dropna=False)
        .agg(windows=("detected", "size"), detected=("detected", "sum"), detection_rate=("detected", "mean"))
        .reset_index()
    )
    benign = results[results["attack_type"].eq("benign")]
    attacks = results[~results["attack_type"].eq("benign")]
    return {
        "test_windows": int(len(results)),
        "benign_false_positive_rate": float(benign["detected"].mean()) if len(benign) else None,
        "attack_detection_rate": float(attacks["detected"].mean()) if len(attacks) else None,
        "by_attack_type": by_attack.to_dict(orient="records"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path(__file__).with_name("nwdaf_threshold_sweep_extended.csv"),
        help="Phase 2.1 extended-sweep CSV.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).with_name("phase2_4_results"))
    parser.add_argument("--rolling-window", type=int, default=3)
    parser.add_argument("--soft-threshold", type=float, default=0.25)
    parser.add_argument("--contamination", type=float, default=0.05, help="Assumed background anomaly rate; sweep later.")
    parser.add_argument("--folds", type=int, default=3, help="Number of grouped stratified folds; first fold is held out.")
    args = parser.parse_args()

    raw = pd.read_csv(args.input)
    required = {"imsi", "timestamp_unix", "attack_type", *BASE_FEATURES}
    missing = required.difference(raw.columns)
    if missing:
        raise ValueError(f"Input is missing required columns: {sorted(missing)}")

    data = add_rolling_features(raw, args.rolling_window, args.soft_threshold)
    train, test = grouped_stratified_split(data, args.folds)
    benign_train = train[train["attack_type"].eq("benign")]
    if benign_train.empty:
        raise ValueError("Grouped split yielded no benign training rows; change --folds or collect more benign data.")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {
        "configuration": {
            "contamination": args.contamination,
            "n_estimators": 100,
            "random_state": 42,
            "rolling_window": args.rolling_window,
            "soft_threshold": args.soft_threshold,
            "split": "StratifiedGroupKFold over IMSI; first fold held out",
        },
        "rows": {"total": int(len(data)), "train": int(len(train)), "test": int(len(test)), "benign_train": int(len(benign_train))},
        "imsis": {"train": sorted(train["imsi"].astype(str).unique().tolist()), "test": sorted(test["imsi"].astype(str).unique().tolist())},
        "models": {},
    }

    for name, features in MODEL_FEATURES.items():
        model = IsolationForest(n_estimators=100, contamination=args.contamination, random_state=42)
        model.fit(benign_train[features])
        results = evaluate(model, features, test)
        results.to_csv(args.output_dir / f"{name}_predictions.csv", index=False)
        report["models"][name] = {"features": features, **summary(results)}

    data.to_csv(args.output_dir / "phase2_2_features.csv", index=False)
    with (args.output_dir / "evaluation_summary.json").open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
