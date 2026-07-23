import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

DEFAULT_PORT = int(os.environ.get("ML_SERVICE_PORT", "8000"))
MODEL_PATH = Path(os.environ.get("ML_MODEL_PATH", ROOT / "model.joblib"))

_dataset_path = os.environ.get("ML_DATASET_PATH")
if _dataset_path:
    DATASET_PATH = Path(_dataset_path)
else:
    default_path = ROOT / "dataset.csv"
    fallback_path = ROOT.parent / "core" / "nf" / "nwdaf_feature_dataset.csv"
    DATASET_PATH = default_path if default_path.exists() else fallback_path

FEATURE_NAMES = [
    "AUTH.Att",
    "AUTH.Fail",
    "AUTH.FailMAC",
    "SM.SessAtt",
    "SM.SessFail",
]
