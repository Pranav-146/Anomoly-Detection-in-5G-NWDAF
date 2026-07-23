import json
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ml_service.config import DEFAULT_PORT
from ml_service.predictor import Predictor

app = FastAPI(title="NWDAF ML Service")
predictor = Predictor()


class PredictionRequest(BaseModel):
    features: list[float]


class PredictionResponse(BaseModel):
    prediction: bool
    confidence: float


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok"}


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest) -> PredictionResponse:
    predictor.train_if_missing()
    try:
        result = predictor.predict(request.features)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PredictionResponse(**result)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=DEFAULT_PORT)
