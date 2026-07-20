# NWDAF anomaly-detection experiments

## Phase 2.4 - Benign-only Isolation Forest training

Run the training and held-out evaluation from the repository root:

```powershell
python -m pip install -r experiments/requirements.txt
python experiments/train_isolation_forest.py
```

The script consumes `nwdaf_threshold_sweep_extended.csv`, rebuilds the Phase
2.2 per-IMSI rolling features, and uses `StratifiedGroupKFold` with IMSI as
the group. This is important: windows for the same IMSI cannot appear in both
training and test data, avoiding identity/time-series leakage.

Two reproducible detectors are fitted only on the benign rows from the
training partition (`n_estimators=100`, `contamination=0.05`,
`random_state=42`):

| Model | Features |
| --- | --- |
| A | `auth_attempts`, `auth_failures`, `failure_ratio` |
| B | Model A plus `rolling_mean_ratio`, `rolling_max_ratio`, `windows_above_soft_thresh`, `ratio_slope` |

`contamination=0.05` is an initial assumed background anomaly rate, not a
ground-truth attack rate. Sweep it before making an operational choice.
Isolation Forest is tree-based, so no feature scaling is applied. Its
predictions are mapped exactly as sklearn defines them: `-1` is an anomaly
(`detected=True`) and `1` is normal.

The following generated files are written to `experiments/phase2_4_results/`:

- `phase2_2_features.csv` - source rows with regenerated rolling features.
- `model_a_predictions.csv` and `model_b_predictions.csv` - holdout scores and detections.
- `evaluation_summary.json` - configuration, disjoint IMSI sets, per-attack detection rates, and benign false-positive rate.

The supplied sweep is deliberately small (only four benign windows). It is
enough to exercise the end-to-end experiment but not to claim a production
quality detector; collect substantially more benign time windows before
comparing Model A and Model B in the report.
