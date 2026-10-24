"""Train the ML layer from the randomised training captures (never from the 5 test scenarios)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import GroupKFold

from detection.ml import Models, transform
from features.extractor import FEATURE_COLUMNS, extract, label_windows


def build_training_table(train_dir: Path) -> pd.DataFrame:
    """Extract and label every training pcap; one row per host-window."""
    frames = []
    for pcap in sorted(train_dir.glob("*.pcap")):
        truth = json.loads(pcap.with_suffix(".json").read_text())
        ex = extract(pcap)
        w = ex.windows
        w["label"] = label_windows(w, truth)
        w["source_pcap"] = pcap.name
        frames.append(w)
        print(f"  {pcap.name}: {ex.n_packets} pkts -> {len(w)} windows {w['label'].value_counts().to_dict()}")
    return pd.concat(frames, ignore_index=True)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--train-dir", default="data/train")
    ap.add_argument("--table", default="data/train_features.csv.gz", help="cached training table (built if missing)")
    ap.add_argument("--rebuild", action="store_true", help="re-extract the training pcaps even if the table exists")
    ap.add_argument("--model", default="models/nids_models.joblib")
    ap.add_argument("--report", default="results/training_report.json")
    args = ap.parse_args(argv)

    table_path = Path(args.table)
    if table_path.exists() and not args.rebuild:
        df = pd.read_csv(table_path)
        print(f"[+] loaded cached training table {table_path} ({len(df)} windows)")
    else:
        print(f"[+] extracting training captures from {args.train_dir}")
        df = build_training_table(Path(args.train_dir))
        df.to_csv(table_path, index=False, compression="gzip")
    X, y, groups = df[FEATURE_COLUMNS], df["label"], df["source_pcap"]
    print("[+] class balance:", y.value_counts().to_dict())

    # Grouped CV: whole captures are held out, so windows of one capture never leak across folds.
    preds = pd.Series(index=df.index, dtype=object)
    for tr, te in GroupKFold(n_splits=3).split(X, y, groups):
        m = Models.fit(X.iloc[tr], y.iloc[tr])
        preds.iloc[te] = m.rf.predict(transform(X.iloc[te]))
    cv = classification_report(y, preds, output_dict=True, zero_division=0)
    print(classification_report(y, preds, zero_division=0))

    models = Models.fit(X, y)
    Path(args.model).parent.mkdir(parents=True, exist_ok=True)
    models.save(args.model)
    imp = sorted(zip(FEATURE_COLUMNS, models.rf.feature_importances_), key=lambda t: -t[1])
    report = {"n_windows": len(df), "class_counts": y.value_counts().to_dict(),
              "grouped_cv_rf": {k: v for k, v in cv.items() if isinstance(v, dict)},
              "grouped_cv_accuracy": cv["accuracy"],
              "iforest_threshold": models.if_threshold,
              "feature_importances": [{"feature": f, "importance": round(float(v), 4)} for f, v in imp]}
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=2))
    print(f"[+] saved {args.model}; top features: " + ", ".join(f"{f}={v:.3f}" for f, v in imp[:6]))


if __name__ == "__main__":
    main()
