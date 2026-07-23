import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
ROOT_STRING = str(ROOT)
while ROOT_STRING in sys.path:
    sys.path.remove(ROOT_STRING)
# Keep the repository importable without putting its token.py ahead of stdlib.
sys.path.append(ROOT_STRING)


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
    assert set(result) == {"anomaly", "score"}
    assert isinstance(result["anomaly"], bool)
    assert isinstance(result["score"], float)


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

    for invalid in ([0, 0, 0, 0, float("nan")], [0, 0, 0, 0, float("inf")]):
        try:
            predictor.validate_features(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected ValueError for non-finite feature")


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
    test_predictor.train(save=True)
    monkeypatch.setattr("ml_service.app.predictor", test_predictor)

    client = TestClient(app)
    response = client.post("/predict", json={"features": [10, 1, 0, 20, 0]})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"anomaly", "score"}
    assert isinstance(body["anomaly"], bool)
    assert isinstance(body["score"], float)

    zero_response = client.post("/predict", json={"features": [0, 0, 0, 0, 0]})
    assert zero_response.status_code == 200

    assert client.post("/predict", json={"features": [1, 2]}).status_code in (400, 422)
    assert client.post("/predict", json={"features": [1, 2, 3, 4, "bad"]}).status_code in (400, 422)
    assert client.post("/predict", json={"features": ["1", 2, 3, 4, 5]}).status_code in (400, 422)


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


def test_health_reports_model_readiness(tmp_path, monkeypatch):
    from ml_service.app import app
    from ml_service.predictor import Predictor

    predictor = Predictor(model_path=tmp_path / "missing.joblib", dataset_path=tmp_path / "missing.csv")
    monkeypatch.setattr("ml_service.app.predictor", predictor)
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "not_ready", "model_ready": False}


def test_missing_empty_and_malformed_datasets(tmp_path):
    from ml_service.predictor import Predictor

    predictor = Predictor(dataset_path=tmp_path / "missing.csv", model_path=tmp_path / "model.joblib")
    try:
        predictor.load_dataset()
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected missing dataset failure")

    for name, content in (("empty.csv", ""), ("malformed.csv", "not,a,csv\"")):
        path = tmp_path / name
        path.write_text(content)
        try:
            Predictor(dataset_path=path, model_path=tmp_path / "model.joblib").load_dataset()
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected invalid dataset failure for {name}")

def test_dataset_rejects_nonfinite_and_insufficient_usable_rows(tmp_path):
    from ml_service.predictor import Predictor

    header = "AUTH.Att,AUTH.Fail,AUTH.FailMAC,SM.SessAtt,SM.SessFail\n"
    short = tmp_path / "short.csv"
    short.write_text(header + "1,1,1,1,1\n")
    try:
        Predictor(dataset_path=short).train(save=False)
    except ValueError as exc:
        assert "at least 5 usable rows" in str(exc)
    else:
        raise AssertionError("Expected insufficient-data failure")

    nonfinite = tmp_path / "nonfinite.csv"
    nonfinite.write_text(header + "nan,1,1,1,1\n" * 5)
    try:
        Predictor(dataset_path=nonfinite).load_dataset()
    except ValueError as exc:
        assert "NaN or infinite" in str(exc)
    else:
        raise AssertionError("Expected non-finite-data failure")

def test_predict_without_model_returns_not_ready(tmp_path):
    from ml_service.app import app
    from ml_service.predictor import Predictor

    monkeypatch_predictor = Predictor(model_path=tmp_path / "missing.joblib")
    import ml_service.app as app_module
    app_module.predictor = monkeypatch_predictor
    response = TestClient(app).post("/predict", json={"features": [0, 0, 0, 0, 0]})
    assert response.status_code == 503


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
