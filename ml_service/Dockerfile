FROM python:3.11-slim

WORKDIR /app

COPY ml_service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ml_service/ ./ml_service/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ML_SERVICE_HOST=0.0.0.0 \
    ML_SERVICE_PORT=8000 \
    ML_MODEL_PATH=/app/ml_service/model.joblib

EXPOSE 8000

CMD ["python3", "-m", "uvicorn", "ml_service.app:app", "--host", "0.0.0.0", "--port", "8000"]