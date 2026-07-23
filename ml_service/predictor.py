import json
from pathlib import Path

import joblib

from ml_service.config import FEATURE_NAMES, MODEL_PATH


class Predictor:
    def __init__(self, model_path: Path | None = None):
        self.model_path = model_path or MODEL_PATH
        self._model = None

    def _load_model(self):
        if self._model is None:
            self._model = joblib.load(self.model_path)
        return self._model

    def predict(self, features):
        if len(features) != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {len(features)}")
        model = self._load_model()
        result = model.predict([features])[0]
        probability = 0.0
        if hasattr(model, "predict_proba"):
            probability = float(model.predict_proba([features])[0][1])
        return {
            "prediction": bool(result),
            "confidence": probability,
        }

    def train_if_missing(self):
        if self.model_path.exists():
            return
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score
        from sklearn.model_selection import train_test_split

        data = [
            [10.0, 1.0, 0.0, 20.0, 0.0, 0],
            [12.0, 2.0, 0.0, 21.0, 0.0, 0],
            [14.0, 4.0, 1.0, 22.0, 0.0, 1],
            [17.0, 6.0, 2.0, 24.0, 1.0, 1],
            [20.0, 8.0, 3.0, 25.0, 2.0, 1],
        ]
        frame = pd.DataFrame(data, columns=[*FEATURE_NAMES, "label"])
        X = frame[FEATURE_NAMES]
        y = frame["label"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model = RandomForestClassifier(random_state=42, n_estimators=20)
        model.fit(X_train, y_train)
        accuracy_score(y_test, model.predict(X_test))
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, self.model_path)
