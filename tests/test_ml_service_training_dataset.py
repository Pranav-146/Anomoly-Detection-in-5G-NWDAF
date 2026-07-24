from ml_service.config import MIN_TRAINING_ROWS
from ml_service.predictor import Predictor


def test_default_training_dataset_has_enough_rows():
    predictor = Predictor()
    dataset = predictor.load_dataset()
    assert len(dataset) >= MIN_TRAINING_ROWS
