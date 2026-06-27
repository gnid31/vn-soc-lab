FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY train/ ./train/
RUN python train/build_dataset.py && python train/train.py

FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY --from=builder /build/model /app/model

ENV MODEL_PATH=/app/model/url_classifier.joblib
ENV THRESHOLD=0.5
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "app:app"]
