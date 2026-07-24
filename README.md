<!-- Copyright (c) 2026 MakeMyTechnology. Licensed under AGPL-3.0-or-later. -->

# Anomaly Detection in 5G NWDAF

This repository combines a 5G core reference implementation with an anomaly-detection pipeline for NWDAF-style analytics. The project demonstrates how abnormal behavior can be detected from authentication and traffic patterns, passed through a security layer, and turned into enforcement actions such as step-up authentication or blocking.

The main components are:

- Core Go services under [core](core) for the 5G network functions and NWDAF analytics logic.
- A webservice under [core/webservice](core/webservice) that exposes NWDAF analytics routes.
- A Python ML service under [ml_service](ml_service) for model training and inference.
- A security-layer demo under [Security Layer](Security%20Layer) that processes event windows and triggers responses.
- Phase 3 demos under [phase3](phase3) that show the closed-loop behavior end to end.

## What this project does

The project is designed to show the full anomaly-detection flow:

1. Network data is ingested and analyzed by NWDAF.
2. Analytics results are exposed through REST APIs.
3. The security layer evaluates suspicious behavior.
4. A closed-loop controller turns detections into actions.

In practical terms, the system can detect abnormal authentication windows, suspicious traffic behavior, and other patterns that suggest a security threat.

## Repository layout

- [core](core) — Go-based 5G core and NWDAF implementation.
- [core/webservice](core/webservice) — HTTP API for NWDAF analytics and data export.
- [ml_service](ml_service) — Python training/prediction service for anomaly detection models.
- [Security Layer](Security%20Layer) — rule-based and ML-assisted security response logic.
- [phase3](phase3) — demos for the closed-loop controller and end-to-end pipeline.
- [orchestrate](orchestrate) — docker-compose and helper scripts for running the stack.
- [tester](tester) — test tooling and feature engineering helpers.

## Requirements

Before running the project, make sure you have:

- Python 3.10+ or 3.11+
- Go 1.22+
- Git
- Optional: Docker if you want to run the full orchestrated stack

## Quick start

### 1) Clone the repository

```bash
git clone <your-repo-url>
cd Anomoly-Detection-in-5G-NWDAF
```

### 2) Create a Python environment

```bash
python3 -m venv .venv
./.venv/bin/pip install -r ml_service/requirements.txt
./.venv/bin/pip install pytest fastapi httpx2 scikit-learn pandas joblib uvicorn
```

### 3) Run the Python demo flow

#### Closed-loop demo

```bash
./.venv/bin/python phase3/run_closed_loop_demo.py
```

This runs a small synthetic detection workflow and shows how detections become enforcement decisions.

#### End-to-end demo

```bash
./.venv/bin/python phase3/run_end_to_end_demo.py
```

This runs a richer demo with benign and attack-like activity and writes a CSV history file to [phase3/end_to_end_demo_history.csv](phase3/end_to_end_demo_history.csv).

#### Security layer demo

```bash
cd "Security Layer"
../.venv/bin/python realtime_engine.py
```

This demonstrates how the security engine processes event windows and raises candidate detections.

### 4) Run the ML service training entry points

```bash
./.venv/bin/python -m ml_service.train --help
```

Or from the ML service folder:

```bash
cd ml_service
../.venv/bin/python train.py --help
```

## Run the Go NWDAF and webservice modules

### NWDAF tests

```bash
cd core/nf
CGO_ENABLED=0 go test ./... -count=1
```

### Webservice tests

```bash
cd ../webservice
CGO_ENABLED=0 go test ./... -count=1
```

## Full verification command

You can verify the main Python and Go paths with this single command:

```bash
cd /home/prajwal/Anomoly-Detection-in-5G-NWDAF
./.venv/bin/python -m pytest -q \
  tests/test_ml_service.py \
  phase3/test_closed_loop_controller.py \
  phase3/test_detection_adapter.py \
  tester/tests/test_engineer_nwdaf_features.py \
  "Security Layer/test_adaptive_authentication_pipeline.py" \
  "Security Layer/test_adaptive_authentication_policy_engine.py" \
  "Security Layer/test_adaptive_hmac_authentication.py" \
  "Security Layer/test_collaborative_risk_propagation.py" \
  "Security Layer/test_contextual_risk_assessment.py" \
  "Security Layer/test_trust_risk_repository.py" && \
cd core/nf && CGO_ENABLED=0 go test ./... -count=1 && \
cd ../webservice && CGO_ENABLED=0 go test ./... -count=1
```

Expected result:

- Python tests: `53 passed`
- Go tests: all relevant NWDAF and webservice packages report `ok`

## Optional: run the full orchestrated stack

If you want the full stack experience, use the orchestration scripts:

```bash
cd orchestrate
./run_studio.sh --role=both
```

Then open:

- http://localhost:5000 for the core UI
- http://localhost:5001 for the tester UI

## Notes

- The system is designed as a reference/demo implementation rather than a production-ready deployment.
- The anomaly-detection flow is intentionally modular so you can experiment with thresholds, ML models, and closed-loop responses.
- For a deeper understanding, start with:
  - [phase3/run_closed_loop_demo.py](phase3/run_closed_loop_demo.py)
  - [phase3/run_end_to_end_demo.py](phase3/run_end_to_end_demo.py)
  - [Security Layer/realtime_engine.py](Security%20Layer/realtime_engine.py)

## License

This project is licensed under the GNU Affero General Public License v3.0 or later.
