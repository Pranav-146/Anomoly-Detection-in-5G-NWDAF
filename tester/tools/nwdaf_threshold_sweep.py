#!/usr/bin/env python3
"""Run a controlled NWDAF ABNORMAL_BEHAVIOUR threshold sweep.

Design / Threat model
---------------------
We want two adversary types and a benign baseline to evaluate NWDAF's
ABNORMAL_BEHAVIOUR analytic.

- "naive_attacker": a single high-ratio data point (e.g. 0.40) sent in one
    window — this should be caught by a correctly tuned detector.
- "paced_evasion": an attacker that paces failed attempts across many
    consecutive windows while keeping each window's failure ratio just below
    the detector threshold (e.g. 0.29–0.30). This targets analyzers that use
    fixed, non-overlapping 30s collection ticks: no single window crosses the
    configured threshold, but aggregate malicious volume is high.
- "benign": realistic low/frequent failure ratios with small random noise.

The script now generates time-varying sequences for the paced evasion
attacker (multiple datapoints spaced by `window_sec`) as well as single-shot
naive attacks and benign samples. It records ground-truth labels in the
`is_attack` and `attack_type` CSV columns; NWDAF's own `detected` column is
kept separately so it cannot be used as a ground-truth label later.

The CSV is suitable for later comparison between NWDAF's verdict and a
customer-side detector (Isolation Forest etc.).
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_RATIOS = (0.05, 0.10, 0.20, 0.29, 0.30, 0.31, 0.40)


def request_json(base_url: str, path: str, method: str = "GET", body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc


def abnormal_result(base_url: str, imsi: str, window_sec: int) -> dict:
    qs = urllib.parse.urlencode({"imsi": imsi, "window_sec": window_sec})
    payload = request_json(base_url, f"/api/nwdaf/analytics/ABNORMAL_BEHAVIOUR?{qs}")
    result = payload.get("result") or {}
    return result.get("result") or {}


def post_datapoint(base_url: str, imsi: str, attempts: int, failures: int, collected_at: float, meta: dict) -> None:
    data_json = {
        "pm_counters": {
            "AUTH.Att": attempts,
            "AUTH.Fail": failures,
            "AUTH.FailMAC": 0,
        },
        "experiment": meta,
    }
    ingest = {
        "source_nf": "AMF",
        "analytics_id": "ABNORMAL_BEHAVIOUR",
        "imsi": imsi,
        "data_json": json.dumps(data_json, separators=(",", ":")),
        "collected_at": collected_at,
    }
    request_json(base_url, "/api/nwdaf/data", "POST", ingest)
    return None


def run_sweep(base_url: str, attempts: int, ratios: list[float], repeats: int, window_sec: int, windows_per_sequence: int = 5) -> list[dict]:
    rows: list[dict] = []
    run_id = int(time.time())

    for repeat in range(repeats):
        # 1) Naive attacker: single-shot high-ratio samples (should be detected)
        for ratio_idx, ratio in enumerate(ratios):
            failures = int(round(attempts * ratio))
            actual_ratio = failures / attempts if attempts else 0.0
            imsi = f"001010{run_id % 1000000:06d}{repeat % 10}{ratio_idx % 10}"
            now = time.time()
            meta = {"name": "nwdaf_threshold_sweep", "repeat": repeat, "target_ratio": ratio, "attack_type": "naive_attacker", "window_sec": window_sec}
            post_datapoint(base_url, imsi, attempts, failures, now, meta)
            result = abnormal_result(base_url, imsi, window_sec)
            alerts = result.get("alerts") or []
            rows.append(
                {
                    "timestamp_unix": f"{now:.3f}",
                    "repeat": repeat,
                    "imsi": imsi,
                    "attack_type": "naive_attacker",
                    "is_attack": True,
                    "auth_attempts": attempts,
                    "auth_failures": failures,
                    "failure_ratio": f"{actual_ratio:.4f}",
                    "detected": bool(result.get("anomaly_detected")),
                    "alert_count": result.get("alert_count", len(alerts)),
                    "alert_types": "|".join(str(a.get("type", "")) for a in alerts),
                    "window_index": "",
                    "campaign_detected": "",
                    "campaign_alert_count": "",
                    "campaign_alert_types": "",
                }
            )

        # 2) Paced evasion attacker: multiple consecutive windows with
        #    per-window ratio held at ~0.29-0.30 so no single window trips a
        #    fixed 30s threshold, but aggregate volume is high.
        paced_ratios = [r for r in ratios if 0.28 <= r <= 0.31]
        for pidx, ratio in enumerate(paced_ratios):
            imsi = f"001010{(run_id+1) % 1000000:06d}{repeat % 10}{pidx % 10}"
            # start so collected_at values are contiguous windows
            start = time.time()
            # Post all windows without querying per-window (to avoid time-travel
            # artefacts). We'll query once after the sequence for a campaign-level
            # verdict.
            for w in range(windows_per_sequence):
                failures = int(round(attempts * ratio))
                actual_ratio = failures / attempts if attempts else 0.0
                collected = start + w * window_sec
                meta = {"name": "nwdaf_threshold_sweep", "repeat": repeat, "target_ratio": ratio, "attack_type": "paced_evasion", "window_sec": window_sec, "window_index": w}
                post_datapoint(base_url, imsi, attempts, failures, collected, meta)
                # record per-injection row; set per-window `detected` unknown/False
                rows.append(
                    {
                        "timestamp_unix": f"{collected:.3f}",
                        "repeat": repeat,
                        "imsi": imsi,
                        "attack_type": "paced_evasion",
                        "is_attack": True,
                        "auth_attempts": attempts,
                        "auth_failures": failures,
                        "failure_ratio": f"{actual_ratio:.4f}",
                        "detected": False,
                        "alert_count": 0,
                        "alert_types": "",
                        "window_index": w,
                        "campaign_detected": False,
                        "campaign_alert_count": 0,
                        "campaign_alert_types": "",
                    }
                )
            # After the sequence, query using a long window to see if the
            # campaign as a whole is detected. Use a small buffer to ensure
            # coverage.
            buffer = 5
            campaign_window = windows_per_sequence * window_sec + buffer
            campaign_result = abnormal_result(base_url, imsi, campaign_window)
            campaign_alerts = campaign_result.get("alerts") or []
            # Update the rows for this imsi to include campaign verdict
            for r in rows:
                if r["imsi"] == imsi and r.get("attack_type") == "paced_evasion":
                    r["campaign_detected"] = bool(campaign_result.get("anomaly_detected"))
                    r["campaign_alert_count"] = campaign_result.get("alert_count", len(campaign_alerts))
                    r["campaign_alert_types"] = "|".join(str(a.get("type", "")) for a in campaign_alerts)

        # 3) Benign baseline: low ratios with small random noise
        benign_ratios = (0.00, 0.01, 0.02, 0.03)
        for bidx, ratio in enumerate(benign_ratios):
            noise = random.uniform(-0.002, 0.002)
            r = max(0.0, ratio + noise)
            failures = int(round(attempts * r))
            actual_ratio = failures / attempts if attempts else 0.0
            imsi = f"001010{(run_id+2) % 1000000:06d}{repeat % 10}{bidx % 10}"
            now = time.time()
            meta = {"name": "nwdaf_threshold_sweep", "repeat": repeat, "target_ratio": r, "attack_type": "benign", "window_sec": window_sec}
            post_datapoint(base_url, imsi, attempts, failures, now, meta)
            result = abnormal_result(base_url, imsi, window_sec)
            alerts = result.get("alerts") or []
            rows.append(
                {
                    "timestamp_unix": f"{now:.3f}",
                    "repeat": repeat,
                    "imsi": imsi,
                    "attack_type": "benign",
                    "is_attack": False,
                    "auth_attempts": attempts,
                    "auth_failures": failures,
                    "failure_ratio": f"{actual_ratio:.4f}",
                    "detected": bool(result.get("anomaly_detected")),
                    "alert_count": result.get("alert_count", len(alerts)),
                    "alert_types": "|".join(str(a.get("type", "")) for a in alerts),
                    "window_index": "",
                    "campaign_detected": "",
                    "campaign_alert_count": "",
                    "campaign_alert_types": "",
                }
            )

    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "timestamp_unix",
        "repeat",
        "imsi",
        "attack_type",
        "is_attack",
        "auth_attempts",
        "auth_failures",
        "failure_ratio",
        "detected",
        "alert_count",
        "alert_types",
        "window_index",
        "campaign_detected",
        "campaign_alert_count",
        "campaign_alert_types",
    )
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:5000")
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--window-sec", type=int, default=30)
    parser.add_argument("--windows-per-sequence", type=int, default=10, help="Number of consecutive windows for paced_evasion sequences")
    parser.add_argument(
        "--ratios",
        default=",".join(str(r) for r in DEFAULT_RATIOS),
        help="Comma-separated failure ratios to test.",
    )
    parser.add_argument(
        "--out",
        default="experiments/nwdaf_threshold_sweep.csv",
        help="CSV output path, relative to the current working directory unless absolute.",
    )
    args = parser.parse_args()

    ratios = [float(x.strip()) for x in args.ratios.split(",") if x.strip()]
    rows = run_sweep(args.base_url, args.attempts, ratios, args.repeat, args.window_sec, args.windows_per_sequence)
    out = Path(args.out)
    write_csv(out, rows)

    print(f"wrote {len(rows)} rows to {out}")
    for row in rows:
        print(
            f"ratio={row['failure_ratio']} failures={row['auth_failures']}/"
            f"{row['auth_attempts']} detected={row['detected']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
