"""Hybrid detection engine: rules + RandomForest + IsolationForest, fused into one explained verdict.

Fusion policy (per host-window)
-------------------------------
1. A rule fired  -> malicious, class = rule class.  Confidence = rule confidence, combined (noisy-OR) with
   the RF probability for that class when the RF agrees.  Both layers agreeing is recorded as corroboration.
2. No rule, RF says attack with p >= 0.5 -> malicious (ML-only detection), confidence = RF probability.
3. Neither, but the IsolationForest score is below its benign threshold -> "anomaly" (low severity):
   something unusual that no signature or known class explains; meant for analyst triage.
4. Otherwise benign.

Severity: dos/arpspoof = high, portscan/bruteforce = medium, anomaly = low; a detection made by only one
layer with confidence < 0.6 is lowered one level; a brute force confirmed by both layers is raised to high.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from detection.ml import Models
from detection.rules import evaluate_rules, evaluate_victims
from features.extractor import Extraction, extract

LEVELS = ["low", "medium", "high"]
BASE_SEVERITY = {"dos": "high", "arpspoof": "high", "portscan": "medium", "bruteforce": "medium", "anomaly": "low"}
DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "nids_models.joblib"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Result:
    """Output of one analysis run."""

    pcap: str
    windows: pd.DataFrame
    events: list[dict]
    victim_alerts: list[dict]
    arp_events: list[dict]
    flows: pd.DataFrame
    timing: dict = field(default_factory=dict)

    def events_frame(self) -> pd.DataFrame:
        """Flat table of flagged events (one row per flagged host-window)."""
        rows = [{k: e[k] for k in ("event_id", "window_start", "window_end", "src", "dsts", "dst_ports", "verdict",
                                    "severity", "confidence", "layers", "rule_ids", "why")} for e in self.events]
        return pd.DataFrame(rows)


def fuse(row: pd.Series, rule_hits: list[dict], ml: pd.Series, models: Models) -> dict | None:
    """Combine the three layers for one window. Returns an event dict or None (benign)."""
    rf_class, rf_p = ml["rf_class"], float(ml["rf_conf"])
    layers: list[str] = []
    if rule_hits:
        best = max(rule_hits, key=lambda h: (LEVELS.index(h["severity"]), h["confidence"]))
        verdict = best["label"]
        conf = best["confidence"]
        layers.append("rules")
        p_same = float(ml.get(f"p_{verdict}", 0.0))
        if p_same >= 0.5:
            layers.append("rf")
            conf = 1 - (1 - conf) * (1 - p_same)
    elif rf_class != "benign" and rf_p >= 0.5:
        verdict, conf = rf_class, rf_p
        layers.append("rf")
    elif bool(ml["if_anomaly"]):
        verdict = "anomaly"
        conf = float(np.clip(0.5 + (models.if_threshold - ml["if_score"]) * 2.0, 0.5, 0.95))
    else:
        return None
    conf = min(conf, 0.99)  # never claim certainty
    if bool(ml["if_anomaly"]):
        layers.append("iforest")
    sev = BASE_SEVERITY[verdict]
    core = [l for l in layers if l in ("rules", "rf")]
    if verdict != "anomaly" and len(core) == 1 and conf < 0.6:
        sev = LEVELS[max(0, LEVELS.index(sev) - 1)]
    if verdict == "bruteforce" and len(core) == 2:
        sev = "high"

    contribs = models.top_contributions(row)
    why_parts = []
    for h in rule_hits:
        checks = " and ".join(f'{c["feature"]}={c["observed"]:g} {c["op"]} {c["threshold"]:g}' for c in h["checks"])
        why_parts.append(f'{h["rule_id"]} ({h["name"]}): {checks}')
    why_parts.append(f"RF: {rf_class} p={rf_p:.2f}")
    if contribs:
        why_parts.append("top features: " + ", ".join(
            f'{c["feature"]}={c["observed"]:g} (benign median {c["benign_median"]:g})' for c in contribs))
    why_parts.append(f'IsolationForest score {ml["if_score"]:.3f} (threshold {models.if_threshold:.3f})'
                     + (" ANOMALOUS" if ml["if_anomaly"] else ""))
    return {
        "verdict": verdict, "severity": sev, "confidence": round(float(conf), 3), "layers": "+".join(layers),
        "rule_ids": ",".join(h["rule_id"] for h in rule_hits),
        "why": " | ".join(why_parts),
        "details": {"rules": rule_hits, "rf": {"class": rf_class, "confidence": round(rf_p, 3),
                                               "proba": {c: round(float(ml[f"p_{c}"]), 3) for c in
                                                         ("benign", "portscan", "dos", "bruteforce", "arpspoof")}},
                    "top_features": contribs,
                    "iforest": {"score": round(float(ml["if_score"]), 4), "threshold": round(models.if_threshold, 4),
                                "anomalous": bool(ml["if_anomaly"])}},
    }


def analyze(pcap: str | Path, models: Models | None = None, extraction: Extraction | None = None) -> Result:
    """Run extraction (unless given) and hybrid detection on one capture."""
    models = models or Models.load(DEFAULT_MODEL)
    ex = extraction or extract(pcap)
    t0 = time.perf_counter()
    w = ex.windows.copy()
    hits = evaluate_rules(w)
    ml = models.predict(w)
    t_models = time.perf_counter()
    events: list[dict] = []
    verdicts, sevs, confs = [], [], []
    for i, (idx, row) in enumerate(w.iterrows()):
        ev = fuse(row, hits[i], ml.loc[idx], models)
        verdicts.append(ev["verdict"] if ev else "benign")
        sevs.append(ev["severity"] if ev else "")
        confs.append(ev["confidence"] if ev else 0.0)
        if ev:
            ev.update({"event_id": f"EVT-{len(events) + 1:04d}", "src": row["entity"],
                       "window_start": iso(row["window_start"]), "window_end": iso(row["window_end"]),
                       "dsts": row["top_dsts"], "dst_ports": row["top_ports"],
                       "observed": {k: round(float(row[k]), 3) for k in ("pkts", "pkt_rate", "n_flows", "n_dst_ports",
                                                                        "syn_count", "handshake_completion",
                                                                        "auth_failures", "arp_ip_mac_changes")}})
            events.append(ev)
    w = pd.concat([w, ml], axis=1)
    w["rule_ids"] = [",".join(h["rule_id"] for h in hh) for hh in hits]
    w["verdict"], w["severity"], w["confidence"] = verdicts, sevs, confs
    victims = evaluate_victims(ex.victims)
    for v in victims:
        v["window_start_iso"] = iso(v["window_start"])
    t1 = time.perf_counter()
    det = t1 - t0
    total = ex.seconds + det
    timing = {"packets": ex.n_packets, "capture_seconds": round(ex.duration, 2), "windows": len(w),
              "extract_s": round(ex.seconds, 3), "detect_s": round(det, 3), "models_s": round(t_models - t0, 3),
              "total_s": round(total, 3), "packets_per_s": round(ex.n_packets / total, 1) if total else 0.0,
              "ms_per_window": round(1000 * det / max(len(w), 1), 3),
              "realtime_factor": round(ex.duration / total, 1) if total else 0.0}
    return Result(str(pcap), w, events, victims, ex.arp_events, ex.flows, timing)
