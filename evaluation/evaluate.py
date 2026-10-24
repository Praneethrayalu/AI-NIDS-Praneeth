"""Evaluate the hybrid detector on the five mandatory scenarios.

Outputs (results/):
  metrics.json            every number below, machine readable
  metrics_summary.md      tables used in the README / report
  alerts/<scenario>.json  full explained alerts, alerts/<scenario>.csv flat table
  figures/*.png           confusion matrices, ablation, throughput, DoS impact timeline, feature importance

Unit of evaluation = host-window (one source x one 10 s window), labelled from the generator's ground truth.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("MPLBACKEND", "Agg")
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import confusion_matrix  # noqa: E402

from detection.engine import DEFAULT_MODEL, analyze  # noqa: E402
from detection.ml import Models  # noqa: E402
from features.extractor import extract, label_windows  # noqa: E402
from traffic.generate import SCENARIOS, SERVER_IP  # noqa: E402

CLASS_ORDER = ["benign", "portscan", "dos", "bruteforce", "arpspoof", "anomaly"]
NICE = {"s1_benign": "S1 Benign", "s2_portscan": "S2 Port scan", "s3_dos": "S3 SYN flood",
        "s4_bruteforce_arp": "S4 Brute force + ARP", "s5_ambiguous": "S5 Ambiguous"}


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Precision / recall / F1 / accuracy and the raw confusion counts (positive = malicious)."""
    tp = int(np.sum(y_true & y_pred)); fp = int(np.sum(~y_true & y_pred))
    fn = int(np.sum(y_true & ~y_pred)); tn = int(np.sum(~y_true & ~y_pred))
    p = tp / (tp + fp) if tp + fp else (1.0 if tp + fn == 0 else 0.0)
    r = tp / (tp + fn) if tp + fn else None  # undefined when a scenario has no malicious windows
    f1 = (2 * p * r / (p + r) if (p + r) else 0.0) if r is not None else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 4), "recall": None if r is None else round(r, 4),
            "f1": None if f1 is None else round(f1, 4), "accuracy": round((tp + tn) / max(len(y_true), 1), 4),
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0}


def layer_predictions(w: pd.DataFrame) -> dict[str, np.ndarray]:
    return {"rules only": (w["rule_ids"] != "").to_numpy(),
            "RandomForest only": ((w["rf_class"] != "benign") & (w["rf_conf"] >= 0.5)).to_numpy(),
            "IsolationForest only": w["if_anomaly"].to_numpy(dtype=bool),
            "hybrid (final)": (w["verdict"] != "benign").to_numpy(),
            "hybrid, medium+ severity": ((w["verdict"] != "benign") & w["severity"].isin(["medium", "high"])).to_numpy()}


def dos_impact(flows: pd.DataFrame, truth: dict, bucket: float = 5.0) -> pd.DataFrame:
    """Service impact seen in the capture: benign clients' SYN->SYN/ACK time and unanswered SYNs to the web server."""
    bots = set(a for atk in truth["attacks"] for a in atk["srcs"])
    f = flows[(flows["dst"] == SERVER_IP) & (flows["dport"] == 80) & (flows["proto"] == "tcp") & flows["syn"]
              & ~flows["src"].isin(bots)].copy()
    t0 = truth["base_ts"]
    f["t"] = ((f["start"] - t0) // bucket) * bucket
    g = f.groupby("t").agg(attempts=("syn", "size"), answered=("synack", "sum"),
                          rtt_ms=("handshake_rtt", lambda s: float(np.nanmedian(s.dropna())) * 1000 if s.notna().any() else np.nan))
    g["unanswered_pct"] = 100 * (1 - g["answered"] / g["attempts"])
    return g.reset_index()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", default="data")
    ap.add_argument("--model", default=str(DEFAULT_MODEL))
    ap.add_argument("--out", default="results")
    args = ap.parse_args(argv)
    out, figs, alerts_dir = Path(args.out), Path(args.out) / "figures", Path(args.out) / "alerts"
    figs.mkdir(parents=True, exist_ok=True); alerts_dir.mkdir(parents=True, exist_ok=True)
    models = Models.load(args.model)

    per_scn, all_w, timings, attacks, examples = {}, [], {}, [], {"TP": [], "FP": [], "FN": []}
    s3_extra = None
    for scn in SCENARIOS:
        pcap = Path(args.data) / "pcaps" / f"{scn}.pcap"
        truth = json.loads((Path(args.data) / "ground_truth" / f"{scn}.json").read_text())
        ex = extract(pcap)
        res = analyze(pcap, models, extraction=ex)
        w = res.windows
        w["label"] = label_windows(w, truth)
        w["scenario"] = scn
        yt = (w["label"] != "benign").to_numpy()
        per_scn[scn] = {"description": truth["description"], "windows": len(w),
                        "malicious_windows": int(yt.sum()),
                        "layers": {k: binary_metrics(yt, v) for k, v in layer_predictions(w).items()},
                        "verdict_counts": w.loc[w["verdict"] != "benign", "verdict"].value_counts().to_dict(),
                        "victim_alerts": len(res.victim_alerts)}
        timings[scn] = res.timing
        # attack-level detection and time to detect
        for atk in truth["attacks"]:
            m = w[w["entity"].isin(atk["srcs"]) & (w["label"] == atk["label"])]
            hit = m[m["verdict"] != "benign"]
            delay = float(hit["window_end"].min() - atk["start"]) if len(hit) else None
            attacks.append({"scenario": scn, "attack": atk["label"], "note": atk["note"], "windows": len(m),
                            "windows_flagged": len(hit), "detected": bool(len(hit)),
                            "correct_class": bool((hit["verdict"] == atk["label"]).any()),
                            "time_to_detect_s": None if delay is None else round(max(delay, 0.0), 1)})
        # examples
        for _, r in w.iterrows():
            kind = ("TP" if r["label"] != "benign" and r["verdict"] != "benign" else
                    "FP" if r["label"] == "benign" and r["verdict"] != "benign" else
                    "FN" if r["label"] != "benign" else None)
            if r["label"] != "benign" and r["severity"] not in ("medium", "high"):
                kind_mp = "FN at medium+ severity"
                examples.setdefault(kind_mp, [])
                if len([e for e in examples[kind_mp] if e["scenario"] == scn]) < 3:
                    examples[kind_mp].append({"scenario": scn, "src": r["entity"], "label": r["label"],
                                              "window_start": pd.Timestamp(r["window_start"], unit="s").strftime("%H:%M:%S"),
                                              "verdict": r["verdict"], "severity": r["severity"] or "none",
                                              "rf": f'{r["rf_class"]} p={r["rf_conf"]:.2f}', "if_score": round(float(r["if_score"]), 4),
                                              "rules": r["rule_ids"] or "none"})
            if kind and len([e for e in examples[kind] if e["scenario"] == scn]) < 3:
                ev = next((e for e in res.events if e["src"] == r["entity"] and e["window_start"].endswith(
                    pd.Timestamp(r["window_start"], unit="s").strftime("%H:%M:%S"))), None)
                examples[kind].append({"scenario": scn, "src": r["entity"], "window_start": pd.Timestamp(r["window_start"], unit="s").strftime("%H:%M:%S"),
                                       "label": r["label"], "verdict": r["verdict"], "severity": r["severity"],
                                       "confidence": r["confidence"],
                                       "observed": {k: round(float(r[k]), 3) for k in ("pkts", "n_flows", "n_dst_ports", "syn_count", "handshake_completion", "mean_flow_duration", "auth_service_conns", "max_conn_same_service")},
                                       "rf": f'{r["rf_class"]} p={r["rf_conf"]:.2f}', "if_score": round(float(r["if_score"]), 4),
                                       "why": ev["why"] if ev else "no rule fired; RF benign; IsolationForest score above threshold"})
        (alerts_dir / f"{scn}.json").write_text(json.dumps({"timing": res.timing, "events": res.events,
                                                            "victim_alerts": res.victim_alerts,
                                                            "arp_events": res.arp_events[:50]}, indent=2, default=str))
        res.events_frame().to_csv(alerts_dir / f"{scn}.csv", index=False)
        if scn == "s3_dos":
            s3_extra = (w.copy(), ex, truth, res)
        all_w.append(w)
        print(f"[+] {scn}: {per_scn[scn]['layers']['hybrid (final)']}  ({res.timing['packets_per_s']:.0f} pkt/s)")

    W = pd.concat(all_w, ignore_index=True)
    yt = (W["label"] != "benign").to_numpy()
    overall = {k: binary_metrics(yt, v) for k, v in layer_predictions(W).items()}
    mal = W[W["label"] != "benign"]
    class_acc = float((mal["verdict"] == mal["label"]).mean()) if len(mal) else None

    # ------------------------------------------------------------- figures
    def cm_plot(ax, cm, labels, title):
        ax.imshow(cm, cmap="Blues")
        ax.set_xticks(range(len(labels)), labels, rotation=30, ha="right", fontsize=8)
        ax.set_yticks(range(len(labels)), labels, fontsize=8)
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=9,
                        color="white" if cm[i, j] > cm.max() * 0.6 else "black")
        ax.set_xlabel("predicted"); ax.set_ylabel("true"); ax.set_title(title, fontsize=10)

    fig, axes = plt.subplots(1, 5, figsize=(17, 3.6))
    for ax, scn in zip(axes, SCENARIOS):
        ws = W[W["scenario"] == scn]
        cm = confusion_matrix(ws["label"] != "benign", ws["verdict"] != "benign", labels=[False, True])
        cm_plot(ax, cm, ["benign", "malicious"], NICE[scn])
    fig.tight_layout(); fig.savefig(figs / "confusion_per_scenario.png", dpi=130); plt.close(fig)

    labs_true = [c for c in CLASS_ORDER if c != "anomaly"]
    cm = confusion_matrix(W["label"], W["verdict"], labels=CLASS_ORDER)[: len(labs_true)]
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    ax.imshow(np.log1p(cm), cmap="Blues")
    ax.set_xticks(range(len(CLASS_ORDER)), CLASS_ORDER, rotation=30, ha="right"); ax.set_yticks(range(len(labs_true)), labs_true)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=9, color="white" if np.log1p(cm[i, j]) > np.log1p(cm.max()) * 0.6 else "black")
    ax.set_xlabel("final verdict"); ax.set_ylabel("ground truth"); ax.set_title("Overall multi-class confusion (all 5 scenarios, host-windows)")
    fig.tight_layout(); fig.savefig(figs / "confusion_overall_multiclass.png", dpi=130); plt.close(fig)

    fig, ax = plt.subplots(figsize=(9.5, 3.8))
    names = list(overall)
    x = np.arange(len(names))
    for i, met in enumerate(["precision", "recall", "f1"]):
        vals = [overall[n][met] or 0 for n in names]
        bars = ax.bar(x + (i - 1) * 0.26, vals, 0.26, label=met)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.2f}", ha="center", fontsize=7)
    ax.set_xticks(x, [n.replace(", ", ",\n") for n in names], fontsize=8); ax.set_ylim(0, 1.12); ax.legend(loc="lower right", fontsize=8)
    ax.set_title("Detection layers compared (all scenarios, host-window level)")
    fig.tight_layout(); fig.savefig(figs / "ablation_layers.png", dpi=130); plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 3.4))
    pps = [timings[s]["packets_per_s"] for s in SCENARIOS]
    bars = ax.bar([NICE[s] for s in SCENARIOS], pps, color="#4C78A8")
    for b, s in zip(bars, SCENARIOS):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(), f'{timings[s]["packets_per_s"]:,.0f}\n({timings[s]["packets"]:,} pkts)', ha="center", va="bottom", fontsize=7)
    ax.set_ylabel("packets / second processed"); ax.set_ylim(0, max(pps) * 1.3)
    ax.set_title("Offline throughput (extraction + detection, one Python process, 4-vCPU box)")
    fig.tight_layout(); fig.savefig(figs / "throughput.png", dpi=130); plt.close(fig)

    imp = sorted(zip(models.rf.feature_names_in_ if hasattr(models.rf, "feature_names_in_") else
                     __import__("features.extractor", fromlist=["FEATURE_COLUMNS"]).FEATURE_COLUMNS,
                     models.rf.feature_importances_), key=lambda t: t[1])[-12:]
    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.barh([f for f, _ in imp], [v for _, v in imp], color="#F58518")
    ax.set_title("RandomForest feature importance (top 12)"); ax.set_xlabel("mean decrease in impurity")
    fig.tight_layout(); fig.savefig(figs / "feature_importance.png", dpi=130); plt.close(fig)

    impact = None
    if s3_extra:
        w3, ex3, truth3, res3 = s3_extra
        t0 = truth3["base_ts"]
        per_sec = w3.groupby("window_start")["pkts"].sum() / 10.0
        impact = dos_impact(ex3.flows, truth3)
        fig, (a1, a2) = plt.subplots(2, 1, figsize=(9, 5.2), sharex=True)
        a1.plot(per_sec.index - t0, per_sec.values, drawstyle="steps-post", color="#4C78A8")
        flagged = w3[(w3["verdict"] == "dos")]["window_start"].unique()
        for ws in flagged:
            a1.axvspan(ws - t0, ws - t0 + 10, color="red", alpha=0.12)
        a1.set_ylabel("packets/s (all hosts)"); a1.set_title("S3 SYN flood: traffic rate (red = windows flagged as DoS)")
        a2.plot(impact["t"], impact["rtt_ms"], marker="o", ms=3, label="benign SYN->SYN/ACK median (ms)")
        a2b = a2.twinx()
        a2b.bar(impact["t"] + 2.5, impact["unanswered_pct"], width=4, alpha=0.3, color="red", label="unanswered SYNs %")
        a2.set_ylabel("handshake ms"); a2b.set_ylabel("% unanswered"); a2.set_xlabel("seconds from capture start")
        a2.set_title("Impact on legitimate clients of the web server (from the capture)")
        a2.legend(loc="upper left", fontsize=7); a2b.legend(loc="upper right", fontsize=7)
        fig.tight_layout(); fig.savefig(figs / "s3_dos_timeline.png", dpi=130); plt.close(fig)

    # ------------------------------------------------------------- metrics
    def impact_summary(df):
        if df is None or df.empty:
            return None
        during = df[(df["t"] >= 40) & (df["t"] < 70)]
        before = df[df["t"] < 40]
        return {"before_rtt_ms_median": round(float(np.nanmedian(before["rtt_ms"])), 2),
                "during_rtt_ms_median": round(float(np.nanmedian(during["rtt_ms"])), 2),
                "before_unanswered_pct": round(float(100 * (1 - before["answered"].sum() / before["attempts"].sum())), 1),
                "during_unanswered_pct": round(float(100 * (1 - during["answered"].sum() / during["attempts"].sum())), 1)}

    metrics = {"unit": "host-window (source x 10 s)", "per_scenario": per_scn, "overall": overall,
               "class_accuracy_on_detected_malicious": None if class_acc is None else round(class_acc, 4),
               "attacks": attacks, "timing": timings, "dos_impact": impact_summary(impact), "examples": examples,
               "if_threshold": models.if_threshold}
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))

    md = ["| Scenario | windows | malicious | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"  # noqa: E731
    for scn in SCENARIOS:
        m = per_scn[scn]["layers"]["hybrid (final)"]
        md.append(f"| {NICE[scn]} | {per_scn[scn]['windows']} | {per_scn[scn]['malicious_windows']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['accuracy'])} |")
    m = overall["hybrid (final)"]
    md.append(f"| **Overall** | {len(W)} | {int(yt.sum())} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['accuracy'])} |")
    md += ["", "| Layer | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
    for k, m in overall.items():
        md.append(f"| {k} | {m['tp']} | {m['fp']} | {m['fn']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} |")
    md += ["", "| Attack | windows | flagged | detected | right class | time to detect (s) |", "|---|---|---|---|---|---|"]
    for a in attacks:
        md.append(f"| {a['note']} | {a['windows']} | {a['windows_flagged']} | {a['detected']} | {a['correct_class']} | {a['time_to_detect_s']} |")
    md += ["", "| Scenario | packets | extract s | detect s | packets/s | ms/window | x real time |", "|---|---|---|---|---|---|---|"]
    for scn in SCENARIOS:
        t = timings[scn]
        md.append(f"| {NICE[scn]} | {t['packets']} | {t['extract_s']} | {t['detect_s']} | {t['packets_per_s']:.0f} | {t['ms_per_window']} | {t['realtime_factor']} |")
    (out / "metrics_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\nclass accuracy on malicious windows: {class_acc}")
    print("DoS impact:", metrics["dos_impact"])


if __name__ == "__main__":
    main()
