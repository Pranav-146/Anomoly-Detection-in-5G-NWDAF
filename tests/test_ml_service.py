import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_predictor_train_and_predict(tmp_path):
    from ml_service.predictor import Predictor

    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text(
        "AUTH.Att,AUTH.Fail,AUTH.FailMAC,SM.SessAtt,SM.SessFail\n"
        "10,1,0,20,0\n"
        "12,2,0,21,0\n"
        "14,4,1,22,0\n"
        "15,5,1,23,1\n"
        "18,6,1,24,1\n"
    )
    model_path = tmp_path / "model.joblib"

    predictor = Predictor(model_path=model_path, dataset_path=dataset_path)
    predictor.train(save=True)

    assert model_path.exists()
    result = predictor.predict([10.0, 1.0, 0.0, 20.0, 0.0])
    assert isinstance(result["prediction"], bool)
    assert 0.0 <= result["confidence"] <= 1.0


def test_predictor_invalid_features(tmp_path):
    from ml_service.predictor import Predictor

    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text(
        "AUTH.Att,AUTH.Fail,AUTH.FailMAC,SM.SessAtt,SM.SessFail\n"
        "10,1,0,20,0\n"
        "12,2,0,21,0\n"
        "14,4,1,22,0\n"
        "15,5,1,23,1\n"
        "18,6,1,24,1\n"
    )
    predictor = Predictor(dataset_path=dataset_path, model_path=tmp_path / "model.joblib")

    try:
        predictor.train(save=False)
    except Exception:
        pass

    try:
        predictor.predict([10.0, 1.0, 0.0, 20.0])
    except ValueError as exc:
        assert "expected 5 features" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid feature length")


def test_dataset_header_validation(tmp_path):
    from ml_service.predictor import Predictor

    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text("A,B,C,D,E\n1,2,3,4,5\n")
    predictor = Predictor(dataset_path=dataset_path, model_path=tmp_path / "model.joblib")

    try:
        predictor.load_dataset()
    except ValueError as exc:
        assert "dataset header must match exact feature order" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid dataset header")


def test_app_predict_endpoint(tmp_path, monkeypatch):
    from ml_service.app import app
    from ml_service.predictor import Predictor

    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text(
        "AUTH.Att,AUTH.Fail,AUTH.FailMAC,SM.SessAtt,SM.SessFail\n"
        "10,1,0,20,0\n"
        "12,2,0,21,0\n"
        "14,4,1,22,0\n"
        "15,5,1,23,1\n"
        "18,6,1,24,1\n"
    )
    model_path = tmp_path / "model.joblib"
    test_predictor = Predictor(model_path=model_path, dataset_path=dataset_path)
    monkeypatch.setattr("ml_service.app.predictor", test_predictor)

    client = TestClient(app)
    response = client.post("/predict", json={"features": [10, 1, 0, 20, 0]})
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] in [True, False]
    assert 0.0 <= body["confidence"] <= 1.0


def test_app_train_endpoint(tmp_path, monkeypatch):
    from ml_service.app import app
    from ml_service.predictor import Predictor

    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text(
        "AUTH.Att,AUTH.Fail,AUTH.FailMAC,SM.SessAtt,SM.SessFail\n"
        "10,1,0,20,0\n"
        "12,2,0,21,0\n"
        "14,4,1,22,0\n"
        "15,5,1,23,1\n"
        "18,6,1,24,1\n"
    )
    model_path = tmp_path / "model.joblib"
    test_predictor = Predictor(model_path=model_path, dataset_path=dataset_path)
    monkeypatch.setattr("ml_service.app.predictor", test_predictor)

    client = TestClient(app)
    response = client.post("/train")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "trained"
    assert model_path.exists()


def test_train_script_invocations(tmp_path):
    dataset_path = tmp_path / "dataset.csv"
    dataset_path.write_text(
        "AUTH.Att,AUTH.Fail,AUTH.FailMAC,SM.SessAtt,SM.SessFail\n"
        "10,1,0,20,0\n"
        "12,2,0,21,0\n"
        "14,4,1,22,0\n"
        "15,5,1,23,1\n"
        "18,6,1,24,1\n"
    )
    model_path_module = tmp_path / "model_module.joblib"
    model_path_script = tmp_path / "model_script.joblib"

    module_cmd = [
        sys.executable,
        "-m",
        "ml_service.train",
        "--dataset",
        str(dataset_path),
        "--model",
        str(model_path_module),
    ]
    module_result = subprocess.run(
        module_cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert model_path_module.exists()
    assert "Usable training rows: 5" in module_result.stdout

    script_cmd = [
        sys.executable,
        "train.py",
        "--dataset",
        str(dataset_path),
        "--model",
        str(model_path_script),
    ]
    script_result = subprocess.run(
        script_cmd,
        cwd=ROOT / "ml_service",
        capture_output=True,
        text=True,
        check=True,
    )
    assert model_path_script.exists()
    assert "Usable training rows: 5" in script_result.stdout
