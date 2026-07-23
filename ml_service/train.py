from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from ml_service.predictor import Predictor
except ImportError:
    from predictor import Predictor


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the NWDAF Isolation Forest model")
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Path to the CSV dataset file",
    )
    parser.add_argument(
        "--model",
        type=Path,
        help="Path where the trained model will be saved",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Estimated fraction of anomalies in the dataset",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random state for reproducible training",
    )

    args = parser.parse_args()
    predictor = Predictor(
        dataset_path=args.dataset,
        model_path=args.model,
        contamination=args.contamination,
        random_state=args.random_state,
    )

    try:
        dataset = predictor.load_dataset()
        model = predictor.train(save=True)
    except Exception as exc:
        print(f"Training failed: {exc}", file=sys.stderr)
        return 1

    print(f"Trained Isolation Forest model saved to: {predictor.model_path}")
    print(f"Dataset used: {predictor.dataset_path}")
    print(f"Usable training rows: {len(dataset)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
