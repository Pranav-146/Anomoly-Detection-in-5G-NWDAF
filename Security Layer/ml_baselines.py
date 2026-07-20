"""
ml_baselines.py — Isolation Forest and One-Class SVM baselines.

These are COMPARATIVE baselines only, trained on the same per-window
authentication-event dataset used by Tier 1/Tier 2. The project's primary
contribution is the rule-based two-stage framework; these models exist to
satisfy the assignment's requirement to compare against simple ML approaches,
and to report TPR/FPR/latency/ROC head-to-head.

Feature vector per window (kept intentionally simple/explainable, matching
the project's stated design goal): [attempts, failures, raw_ratio].
Trained ONE-CLASS on benign-only data (matching Tier 2's own baseline
calibration principle: no attack data seen during training).
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from event_log import WindowEvent


def events_to_features(events: list[WindowEvent]) -> np.ndarray:
    return np.array([[e.attempts, e.failures, e.raw_ratio] for e in events])


def train_isolation_forest(benign_events: list[WindowEvent], contamination=0.02,
                            random_state=42):
    """Returns (scaler, model). Features are standardized before fitting —
    raw features (e.g. attempts spanning 1-3 for benign vs 100 for attacks)
    otherwise miscalibrate the contamination-based decision threshold, even
    though the underlying anomaly score does separate correctly."""
    X = events_to_features(benign_events)
    scaler = StandardScaler().fit(X)
    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(scaler.transform(X))
    return scaler, model


def train_one_class_svm(benign_events: list[WindowEvent], nu=0.05, gamma="scale"):
    X = events_to_features(benign_events)
    scaler = StandardScaler().fit(X)
    model = OneClassSVM(nu=nu, gamma=gamma)
    model.fit(scaler.transform(X))
    return scaler, model


def predict_anomaly(scaler, model, events: list[WindowEvent]) -> np.ndarray:
    """Returns boolean array: True = flagged as anomaly (matches sklearn's -1 output)."""
    X = events_to_features(events)
    preds = model.predict(scaler.transform(X))  # 1 = normal, -1 = anomaly
    return preds == -1


if __name__ == "__main__":
    from event_log import generate_benign_sequence, generate_sustained_attack_sequence

    # Train on a larger pool of benign-only traffic across many synthetic SUPIs
    train_events = []
    for i in range(50):
        train_events += generate_benign_sequence(f"train_supi_{i}", "cellA",
                                                   num_windows=15, seed=i)

    iforest_scaler, iforest = train_isolation_forest(train_events)
    ocsvm_scaler, ocsvm = train_one_class_svm(train_events)

    print("=== Test: held-out benign traffic (want LOW false-positive rate) ===")
    test_benign = generate_benign_sequence("test_benign_supi", "cellA", num_windows=30, seed=999)
    iforest_fp = predict_anomaly(iforest_scaler, iforest, test_benign)
    ocsvm_fp = predict_anomaly(ocsvm_scaler, ocsvm, test_benign)
    print(f"IsolationForest FPR on benign: {iforest_fp.mean():.3f}")
    print(f"OneClassSVM   FPR on benign: {ocsvm_fp.mean():.3f}")

    print("\n=== Test: sustained 29% attacker (want HIGH true-positive rate) ===")
    test_attack = generate_sustained_attack_sequence("test_attack_supi", "cellZ",
                                                       num_windows=10, target_ratio=0.29)
    iforest_tp = predict_anomaly(iforest_scaler, iforest, test_attack)
    ocsvm_tp = predict_anomaly(ocsvm_scaler, ocsvm, test_attack)
    print(f"IsolationForest TPR on 29% attack: {iforest_tp.mean():.3f} "
          f"(flagged {iforest_tp.sum()}/{len(test_attack)} windows)")
    print(f"OneClassSVM   TPR on 29% attack: {ocsvm_tp.mean():.3f} "
          f"(flagged {ocsvm_tp.sum()}/{len(test_attack)} windows)")

    print("\n(These numbers feed directly into the head-to-head comparison")
    print(" against Tier1+Tier2 in evaluate.py)")
