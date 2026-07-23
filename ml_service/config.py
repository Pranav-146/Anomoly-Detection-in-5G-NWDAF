from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "dataset.csv"
MODEL_PATH = ROOT / "model.joblib"
FEATURE_NAMES = [
    "AUTH.Att",
    "AUTH.Fail",
    "AUTH.FailMAC",
    "SM.SessAtt",
    "SM.SessFail",
]
DEFAULT_PORT = 8000
