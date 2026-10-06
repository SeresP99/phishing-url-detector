from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_NAMES, to_row


def load_frame(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    if not {"url", "label"}.issubset(frame.columns):
        raise SystemExit("CSV must have columns: url,label")
    frame = frame.dropna(subset=["url", "label"]).copy()
    frame["label"] = frame["label"].astype(str).str.lower()
    mapping = {"phishing": 1, "malicious": 1, "bad": 1, "1": 1, "benign": 0, "legitimate": 0, "good": 0, "0": 0}
    unknown = sorted(set(frame["label"]) - set(mapping))
    if unknown:
        raise SystemExit(f"Unrecognized labels: {unknown}")
    frame["y"] = frame["label"].map(mapping).astype(int)
    return frame


def matrix(urls: pd.Series) -> np.ndarray:
    return np.array([to_row(url) for url in urls], dtype=float)


def metrics_at_fpr(y_true: np.ndarray, scores: np.ndarray, budget: float) -> dict[str, float]:
    benign_scores = scores[y_true == 0]
    if len(benign_scores) == 0:
        raise SystemExit("No benign URLs in the test split.")
    # Highest benign score we are willing to sit at. Flags above this.
    threshold = float(np.quantile(benign_scores, 1 - budget))
    flagged = scores >= threshold
    phishing = y_true == 1
    benign = y_true == 0
    tp = int((flagged & phishing).sum())
    fp = int((flagged & benign).sum())
    fn = int((~flagged & phishing).sum())
    recall = tp / max(int(phishing.sum()), 1)
    precision = tp / max(tp + fp, 1)
    return {
        "fpr_budget": budget,
        "threshold": threshold,
        "recall": recall,
        "precision": precision,
        "false_positives": fp,
        "true_positives": tp,
        "false_negatives": fn,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/sample_urls.csv"))
    parser.add_argument("--out", type=Path, default=Path("artifacts/metrics.json"))
    parser.add_argument("--fpr", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    frame = load_frame(args.data)
    x = matrix(frame["url"])
    y = frame["y"].to_numpy()
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=args.seed, stratify=y
    )

    models = {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(max_iter=500, class_weight="balanced")),
            ]
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(random_state=args.seed),
    }

    report: dict[str, object] = {
        "rows": int(len(frame)),
        "phishing": int(y.sum()),
        "benign": int((y == 0).sum()),
        "features": FEATURE_NAMES,
        "note": "sample_urls.csv is a teaching set. Replace it before quoting numbers.",
        "models": {},
    }

    for name, model in models.items():
        model.fit(x_train, y_train)
        scores = model.predict_proba(x_test)[:, 1]
        report["models"][name] = {
            "roc_auc": float(roc_auc_score(y_test, scores)),
            "average_precision": float(average_precision_score(y_test, scores)),
            "at_fpr": metrics_at_fpr(y_test, scores, args.fpr),
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
