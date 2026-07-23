import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_predictor_train_and_predict():
    from ml_service.predictor import Predictor

    model_path = ROOT / "ml_service" / "test_model.joblib"
    if model_path.exists():
        model_path.unlink()

    predictor = Predictor(model_path=model_path)
    predictor.train_if_missing()

    result = predictor.predict([10.0, 1.0, 0.0, 20.0, 0.0])
    assert isinstance(result["prediction"], bool)
    assert 0.0 <= result["confidence"] <= 1.0
    assert model_path.exists()
