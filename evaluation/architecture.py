"""Draw the architecture diagram (results/figures/architecture.png)."""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402


def box(ax, x, y, w, h, title, body, color):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=color, ec="#333", lw=1.2))
    ax.text(x + w / 2, y + h - 0.17, title, ha="center", va="top", fontsize=10.5, weight="bold")
    ax.text(x + w / 2, y + h - 0.5, body, ha="center", va="top", fontsize=8, linespacing=1.35)


def arrow(ax, x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", lw=1.4, color="#333"))


def main(path: str = "results/figures/architecture.png") -> None:
    fig, ax = plt.subplots(figsize=(13, 6.2))
    ax.set_xlim(0, 13); ax.set_ylim(0, 6.2); ax.axis("off")
    box(ax, 0.2, 3.3, 2.5, 2.6, "1. Traffic", "traffic/generate.py (scapy)\n5 seeded scenario pcaps\n+ 12 randomised training pcaps\nground-truth JSON\n(or any real .pcap/.pcapng)", "#DCEBFA")
    box(ax, 3.2, 3.3, 2.9, 2.6, "2. Features", "features/extractor.py\nheader parser (snaplen-safe)\nbidirectional flows (5-tuple)\nhost x 10 s windows: 32 features\nvictim view per dst:port\nARP IP-MAC baseline", "#E5F5E0")
    box(ax, 6.6, 4.35, 2.9, 1.55, "3a. Rule layer", "detection/rules.py\n8 Snort-style threshold rules\nSCAN / DOS / BF / ARP\n(DOS-002 on the victim view)", "#FDE7D3")
    box(ax, 6.6, 2.55, 2.9, 1.55, "3b. ML layer", "detection/ml.py\nRandomForest (5 classes)\nIsolationForest (benign-only)", "#FDE7D3")
    box(ax, 10.0, 3.3, 2.8, 2.6, "4. Fusion + XAI", "detection/engine.py\nverdict, confidence,\nseverity low/med/high\nwhy: rule threshold vs observed,\ntop feature contributions,\nanomaly score", "#F2E1F7")
    box(ax, 3.2, 0.2, 2.9, 1.9, "Train", "detection/train.py\ngrouped 3-fold CV\nmodels/nids_models.joblib", "#EEEEEE")
    box(ax, 6.6, 0.2, 2.9, 1.9, "Evaluate", "evaluation/evaluate.py\nP / R / F1 / confusion\nTP-FP-FN examples\nthroughput, DoS impact", "#EEEEEE")
    box(ax, 10.0, 0.2, 2.8, 1.9, "Analyst output", "CLI: python -m nids analyze\n(table + JSON + CSV)\nStreamlit dashboard app.py", "#FFF6C7")
    arrow(ax, 2.7, 4.6, 3.2, 4.6)
    arrow(ax, 6.1, 4.9, 6.6, 5.1); arrow(ax, 6.1, 4.2, 6.6, 3.3)
    arrow(ax, 9.5, 5.1, 10.0, 4.9); arrow(ax, 9.5, 3.3, 10.0, 4.0)
    arrow(ax, 11.4, 3.3, 11.4, 2.1)
    arrow(ax, 4.65, 3.3, 4.65, 2.1); arrow(ax, 6.1, 1.6, 6.6, 1.6); arrow(ax, 6.1, 1.6, 7.3, 2.55)
    ax.set_title("AI-NIDS architecture: hybrid signature + ML intrusion detection with explanations", fontsize=13, weight="bold")
    fig.tight_layout(); fig.savefig(path, dpi=140); plt.close(fig)


if __name__ == "__main__":
    main()
