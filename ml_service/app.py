from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator

from ml_service.config import HOST, PORT
from ml_service.predictor import Predictor

app = FastAPI(title="NWDAF ML Service")
predictor = Predictor()


class PredictionRequest(BaseModel):
    model_config = ConfigDict(strict=True)
    features: list[float]

    @field_validator("features", mode="before")
    @classmethod
    def validate_feature_values(cls, value: object) -> object:
        if not isinstance(value, list):
            raise ValueError("features must be a list of numbers")
        for index, item in enumerate(value):
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                raise ValueError(f"feature at index {index} is not numeric")
        return value


class PredictionResponse(BaseModel):
    anomaly: bool
    score: float


@app.get("/health")
def health() -> dict[str, Any]:
    ready = predictor.model_path.is_file()
    if ready:
        try:
            predictor._load_model()
        except (RuntimeError, FileNotFoundError):
            ready = False
    return {"status": "ready" if ready else "not_ready", "model_ready": ready}


@app.post("/train")
def train() -> dict[str, Any]:
    try:
        predictor.train(save=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"status": "trained", "model_path": str(predictor.model_path)}


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest) -> PredictionResponse:
    try:
        result = predictor.predict(request.features)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return PredictionResponse(**result)


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
