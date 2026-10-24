"""ML layer: a supervised RandomForest (known attack classes) and an IsolationForest (novelty / anomaly).

* Features are log1p-transformed (all are non-negative counts, rates or ratios) so heavy-tailed counts
  such as packets per window do not dominate the IsolationForest's random splits.
* The RandomForest is trained on labelled host-windows from *training* captures generated with different
  seeds, attacker addresses and attack rates than the test scenarios (no test leakage).
* The IsolationForest is fitted on benign training windows only.  Its alert threshold is the 0.2nd
  percentile of benign training scores (IF_QUANTILE), i.e. ~0.2 % false-positive rate on training data.
  A first version used the 1st percentile; on ~3,200 test windows that meant ~30 low-severity alerts on
  harmless tiny windows (e.g. the gateway's ARP replies), so the alert budget was tightened.
* A robust per-feature baseline (median / IQR of benign windows) is stored for explanations.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from features.extractor import FEATURE_COLUMNS

IF_QUANTILE = 0.002
CLASSES = ["benign", "portscan", "dos", "bruteforce", "arpspoof"]


def transform(df: pd.DataFrame) -> np.ndarray:
    """Model input: log1p of the feature columns, in a fixed order."""
    return np.log1p(df[FEATURE_COLUMNS].astype(float).clip(lower=0).to_numpy())


@dataclass
class Models:
    """Fitted models plus everything needed to explain their outputs."""

    rf: RandomForestClassifier
    iforest: IsolationForest
    if_threshold: float
    baseline_median: np.ndarray
    baseline_scale: np.ndarray
    raw_median: dict[str, float]

    # ------------------------------------------------------------------ fit
    @classmethod
    def fit(cls, X: pd.DataFrame, y: pd.Series, seed: int = 42) -> "Models":
        Xt = transform(X)
        rf = RandomForestClassifier(n_estimators=150, max_depth=12, min_samples_leaf=2,
                                    class_weight="balanced", random_state=seed, n_jobs=-1)
        rf.fit(Xt, y)
        benign = Xt[(y == "benign").to_numpy()]
        iforest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1)
        iforest.fit(benign)
        thr = float(np.quantile(iforest.decision_function(benign), IF_QUANTILE))
        med = np.median(benign, axis=0)
        q75, q25 = np.percentile(benign, [75, 25], axis=0)
        scale = np.where((q75 - q25) > 1e-6, q75 - q25, np.std(benign, axis=0) + 0.1)
        raw_med = X[(y == "benign").to_numpy()][FEATURE_COLUMNS].median().to_dict()
        return cls(rf, iforest, thr, med, scale, {k: float(v) for k, v in raw_med.items()})

    # -------------------------------------------------------------- predict
    def predict(self, windows: pd.DataFrame) -> pd.DataFrame:
        """Per-window RF class/probabilities and IsolationForest score."""
        Xt = transform(windows)
        proba = self.rf.predict_proba(Xt)
        classes = list(self.rf.classes_)
        out = pd.DataFrame(proba, columns=[f"p_{c}" for c in classes], index=windows.index)
        for c in CLASSES:
            if f"p_{c}" not in out.columns:
                out[f"p_{c}"] = 0.0
        out["rf_class"] = [classes[i] for i in proba.argmax(axis=1)]
        out["rf_conf"] = proba.max(axis=1)
        out["p_attack"] = 1.0 - out["p_benign"]
        out["if_score"] = self.iforest.decision_function(Xt)
        out["if_anomaly"] = out["if_score"] < self.if_threshold
        return out

    def top_contributions(self, row: pd.Series, k: int = 3) -> list[dict]:
        """Per-sample explanation: RF global importance x robust deviation from the benign baseline."""
        x = transform(row.to_frame().T)[0]
        z = (x - self.baseline_median) / self.baseline_scale
        contrib = self.rf.feature_importances_ * np.abs(z)
        order = np.argsort(contrib)[::-1][:k]
        return [{"feature": FEATURE_COLUMNS[i], "observed": round(float(row[FEATURE_COLUMNS[i]]), 3),
                 "benign_median": round(self.raw_median[FEATURE_COLUMNS[i]], 3),
                 "deviation_iqr": round(float(z[i]), 2), "importance": round(float(self.rf.feature_importances_[i]), 3),
                 "contribution": round(float(contrib[i]), 3)} for i in order if contrib[i] > 0]

    def save(self, path: str | Path) -> None:
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path: str | Path) -> "Models":
        return joblib.load(path)
