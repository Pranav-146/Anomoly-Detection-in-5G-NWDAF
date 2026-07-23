from __future__ import annotations

from math import exp, isfinite
from pathlib import Path
from typing import Iterable

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

try:
    from ml_service.config import DATASET_PATH, FEATURE_NAMES, MIN_TRAINING_ROWS, MODEL_PATH
except ModuleNotFoundError:  # Direct execution from the ml_service directory.
    from config import DATASET_PATH, FEATURE_NAMES, MIN_TRAINING_ROWS, MODEL_PATH


class Predictor:
    def __init__(
        self,
        model_path: Path | None = None,
        dataset_path: Path | None = None,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        if not 0 < contamination <= 0.5:
            raise ValueError("contamination must be greater than 0 and at most 0.5")
        self.model_path = model_path or MODEL_PATH
        self.dataset_path = dataset_path or DATASET_PATH
        self.contamination = contamination
        self.random_state = random_state
        self._model = None

    @staticmethod
    def validate_features(features: Iterable[float]) -> list[float]:
        if not isinstance(features, (list, tuple)):
            raise ValueError("features must be a list of numbers")
        if len(features) != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {len(features)}")
        validated = []
        for index, value in enumerate(features):
            if isinstance(value, bool):
                raise ValueError(f"feature values must be numeric, not bool")
            if not isinstance(value, (int, float)):
                raise ValueError(f"feature at index {index} is not numeric: {value!r}")
            numeric_value = float(value)
            if not isfinite(numeric_value):
                raise ValueError(f"feature at index {index} must be finite")
            validated.append(numeric_value)
        return validated

    def _load_model(self):
        if self._model is None:
            if not self.model_path.exists():
                raise FileNotFoundError(f"model file not found at {self.model_path}")
            try:
                artifact = joblib.load(self.model_path)
            except Exception as exc:
                raise RuntimeError(f"unable to load model file at {self.model_path}: {exc}") from exc
            if not isinstance(artifact, dict) or artifact.get("feature_names") != list(FEATURE_NAMES):
                raise RuntimeError("model artifact is missing the expected feature order metadata")
            self._model = artifact.get("model")
            if self._model is None:
                raise RuntimeError("model artifact does not contain a trained model")
        return self._model

    def load_dataset(self, dataset_path: Path | None = None) -> pd.DataFrame:
        dataset_path = Path(dataset_path or self.dataset_path)
        if not dataset_path.exists():
            raise FileNotFoundError(f"dataset file not found at {dataset_path}")

        try:
            frame = pd.read_csv(dataset_path, keep_default_na=False)
        except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError) as exc:
            raise ValueError(f"unable to read dataset CSV: {exc}") from exc
        if list(frame.columns) != FEATURE_NAMES:
            raise ValueError(
                f"dataset header must match exact feature order: {FEATURE_NAMES}, got {list(frame.columns)}"
            )
        if frame.empty:
            raise ValueError("dataset contains no data rows")
        try:
            numeric = frame.astype(float)
        except (TypeError, ValueError) as exc:
            raise ValueError("dataset contains non-numeric values") from exc
        if (frame == "").any(axis=None):
            raise ValueError("dataset contains missing values")
        if not numeric.map(isfinite).all().all():
            raise ValueError("dataset contains NaN or infinite values")
        filtered = numeric.loc[~(numeric == 0).all(axis=1)]
        if filtered.empty:
            raise ValueError("dataset contains only all-zero rows and cannot be used for training")
        return filtered

    def train(self, save: bool = True) -> IsolationForest:
        dataset = self.load_dataset()
        if dataset.shape[0] < MIN_TRAINING_ROWS:
            raise ValueError(f"dataset must contain at least {MIN_TRAINING_ROWS} usable rows for Isolation Forest training")

        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
        )
        model.fit(dataset)
        self._model = model

        if save:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self.model_path.with_suffix(self.model_path.suffix + ".tmp")
            try:
                joblib.dump({"model": model, "feature_names": list(FEATURE_NAMES)}, temporary_path)
                temporary_path.replace(self.model_path)
            except Exception as exc:
                temporary_path.unlink(missing_ok=True)
                raise RuntimeError(f"unable to save model file at {self.model_path}: {exc}") from exc

        return model

    def train_if_missing(self) -> None:
        if self.model_path.exists():
            return
        self.train(save=True)

    def predict(self, features: Iterable[float]) -> dict[str, float | bool]:
        validated = self.validate_features(features)
        model = self._load_model()
        raw_score = model.decision_function([validated])[0]
        prediction = model.predict([validated])[0]
        return {"anomaly": bool(prediction == -1), "score": self._raw_score_to_confidence(raw_score)}

    @staticmethod
    def _raw_score_to_confidence(raw_score: float) -> float:
        return float(1.0 / (1.0 + exp(raw_score)))


def predict(features: list[float]) -> dict[str, float | bool]:
    """Predict with the configured persisted model."""
    return Predictor().predict(features)
