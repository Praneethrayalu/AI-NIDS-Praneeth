"""Unit / integration tests: generator -> extractor -> rules -> engine."""
from __future__ import annotations

import random
from pathlib import Path

import pandas as pd
import pytest

from detection.rules import RULES, evaluate_rules
from features.extractor import FEATURE_COLUMNS, extract, read_pcap
from traffic.generate import SERVER_IP, Builder, write_pcap

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "models" / "nids_models.joblib"


def _pcap(tmp_path: Path, build) -> Path:
    b = Builder(random.Random(7))
    build(b)
    path = tmp_path / "t.pcap"
    b.packets.sort(key=lambda p: p[0])
    write_pcap(path, b.packets)
    return path


def test_pcap_roundtrip_keeps_wire_length(tmp_path):
    path = _pcap(tmp_path, lambda b: b.tcp_session(0.0, "192.168.10.10", SERVER_IP, 80, b"GET / HTTP/1.1\r\n\r\n", 5000))
    pkts = read_pcap(path)
    assert len(pkts) > 5
    assert max(p.wirelen for p in pkts) > 96  # truncated capture, true length preserved


def test_port_scan_features_and_rule(tmp_path):
    path = _pcap(tmp_path, lambda b: b.syn_scan("192.168.10.66", SERVER_IP, list(range(1, 200)), 1.0, rate=300))
    w = extract(path).windows
    row = w[w["entity"] == "192.168.10.66"].iloc[0]
    assert row["n_dst_ports"] >= 150
    assert row["handshake_completion"] < 0.1
    hits = evaluate_rules(w[w["entity"] == "192.168.10.66"])[0]
    assert any(h["rule_id"] == "SCAN-001" for h in hits)
    chk = {c["feature"]: c for c in hits[0]["checks"]}
    assert chk["n_dst_ports"]["observed"] >= chk["n_dst_ports"]["threshold"]  # explanation carries both values


def test_arp_spoof_detected_and_attributed_to_attacker(tmp_path):
    def build(b):
        b.benign(30, ["192.168.10.10", "192.168.10.11", "192.168.10.12"])
        b.arp_spoof("192.168.10.99", ["192.168.10.11"], 5, 20)
    w = extract(_pcap(tmp_path, build)).windows
    flagged = w[w["arp_ip_mac_changes"] > 0]
    assert set(flagged["entity"]) == {"192.168.10.99"}  # not the gateway whose IP was impersonated
    assert all(any(h["rule_id"] == "ARP-001" for h in hh) for hh in evaluate_rules(flagged))


def test_benign_window_matches_no_rule():
    row = {c: 0.0 for c in FEATURE_COLUMNS}
    row.update({"pkts": 40, "n_flows": 6, "n_dst_ports": 3, "n_dst_ips": 4, "syn_count": 5,
                "handshake_completion": 1.0, "max_conn_same_service": 2, "mean_flow_duration": 0.4})
    assert evaluate_rules(pd.DataFrame([row])) == [[]]


def test_rule_ids_unique():
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.skipif(not MODEL.exists(), reason="train the model first (python -m nids train)")
def test_engine_flags_brute_force_with_explanation(tmp_path):
    from detection.engine import analyze

    def build(b):
        b.benign(30, ["192.168.10.10", "192.168.10.11"])
        b.ssh_bruteforce("203.0.113.45", SERVER_IP, 2, 80, rate=6)
    res = analyze(_pcap(tmp_path, build))
    ev = [e for e in res.events if e["src"] == "203.0.113.45"]
    assert ev and all(e["verdict"] == "bruteforce" for e in ev)
    assert "BF-001" in ev[0]["why"] and 0 < ev[0]["confidence"] <= 1
    assert ev[0]["severity"] in {"medium", "high"}
