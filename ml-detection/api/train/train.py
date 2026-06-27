#!/usr/bin/env python3
"""Train URL classifier — char n-gram TF-IDF + LogisticRegression."""
import csv
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data" / "urls.csv"
OUT_MODEL = ROOT / "model" / "url_classifier.joblib"
OUT_REPORT = ROOT / "model" / "training_report.json"
OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)

with DATA.open() as f:
    rows = list(csv.DictReader(f))
X = np.array([r["url"] for r in rows])
y = np.array([int(r["label"]) for r in rows])
print(f"Loaded {len(rows)} rows | malicious={int(y.sum())} benign={int((y==0).sum())}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        min_df=2,
        max_features=5000,
        lowercase=True,
    )),
    ("clf", LogisticRegression(
        C=1.0, max_iter=1000, class_weight="balanced", random_state=42
    )),
])

pipe.fit(X_train, y_train)
y_pred = pipe.predict(X_test)
y_proba = pipe.predict_proba(X_test)[:, 1]

print("\n=== Classification report ===")
report = classification_report(y_test, y_pred, target_names=["benign", "malicious"], output_dict=True)
print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

auc = roc_auc_score(y_test, y_proba)
print(f"ROC AUC: {auc:.4f}")

joblib.dump(pipe, OUT_MODEL)
print(f"\nModel saved → {OUT_MODEL}")

OUT_REPORT.write_text(json.dumps({
    "auc": auc,
    "test_size": len(y_test),
    "train_size": len(y_train),
    "report": report,
    "model_file": str(OUT_MODEL.name),
    "feature_extraction": "char_wb (2,5) TF-IDF max_features=5000",
    "classifier": "LogisticRegression C=1.0 class_weight=balanced",
}, indent=2))
print(f"Report saved → {OUT_REPORT}")

print("\n=== Spot-check on novel examples ===")
samples = [
    "/dvwa/login.php?id=1' UNION SELECT NULL--",
    "/static/js/main.js",
    "/?file=../../../etc/passwd",
    "/api/v1/products?page=3",
    "/<script>alert(1)</script>",
    "/blog/post/secure-coding-tips",
]
probs = pipe.predict_proba(samples)[:, 1]
for s, p in zip(samples, probs):
    flag = "MALICIOUS" if p > 0.5 else "benign   "
    print(f"  {flag} p={p:.3f}  {s}")
