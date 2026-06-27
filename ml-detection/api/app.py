"""Flask API — URL malicious classifier serve."""
import os
from pathlib import Path

import joblib
from flask import Flask, jsonify, request

MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/app/model/url_classifier.joblib"))
THRESHOLD = float(os.environ.get("THRESHOLD", "0.5"))

app = Flask(__name__)
model = joblib.load(MODEL_PATH)
app.logger.info(f"Loaded model: {MODEL_PATH}")


@app.get("/health")
def health():
    return jsonify(status="ok", threshold=THRESHOLD, model=str(MODEL_PATH.name))


@app.post("/predict")
def predict():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "")
    if not url:
        return jsonify(error="missing 'url' field"), 400

    proba = float(model.predict_proba([url])[0][1])
    label = "malicious" if proba >= THRESHOLD else "benign"
    return jsonify(url=url, score=round(proba, 4), label=label, threshold=THRESHOLD)


@app.post("/predict_batch")
def predict_batch():
    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls", [])
    if not urls or not isinstance(urls, list):
        return jsonify(error="missing 'urls' array"), 400

    probas = model.predict_proba(urls)[:, 1].tolist()
    results = [
        {"url": u, "score": round(p, 4), "label": "malicious" if p >= THRESHOLD else "benign"}
        for u, p in zip(urls, probas)
    ]
    return jsonify(results=results, threshold=THRESHOLD)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
