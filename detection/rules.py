"""Signature / threshold layer, written in the spirit of Snort's detection_filter and sfPortscan.

Each rule is evaluated per host-window (source entity x 10 s window).  All conditions of a rule must
hold.  The first condition is the *primary* one: its observed/threshold ratio drives the rule's
confidence.  The Snort-style text next to each rule is the equivalent signature an analyst would
recognise; it is documentation, the Python conditions are what actually runs.
"""
from __future__ import annotations

import math
import operator
from dataclasses import dataclass

import pandas as pd

OPS = {">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt}


@dataclass(frozen=True)
class Condition:
    feature: str
    op: str
    threshold: float

    def holds(self, value: float) -> bool:
        return OPS[self.op](value, self.threshold)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    label: str
    severity: str
    conditions: tuple[Condition, ...]
    snort: str

    def match(self, row: pd.Series) -> dict | None:
        """Return a structured explanation if every condition holds for this window, else None."""
        if not all(c.holds(float(row[c.feature])) for c in self.conditions):
            return None
        primary = self.conditions[0]
        obs = float(row[primary.feature])
        ratio = obs / primary.threshold if primary.op in (">=", ">") and primary.threshold > 0 else 1.0
        confidence = min(0.99, 0.70 + 0.10 * math.log2(max(ratio, 1.0)))
        return {
            "rule_id": self.rule_id, "name": self.name, "label": self.label, "severity": self.severity,
            "confidence": round(confidence, 3),
            "checks": [{"feature": c.feature, "op": c.op, "threshold": c.threshold,
                        "observed": round(float(row[c.feature]), 3)} for c in self.conditions],
            "snort": self.snort,
        }


RULES: tuple[Rule, ...] = (
    Rule("SCAN-001", "TCP SYN port scan (vertical)", "portscan", "medium",
         (Condition("n_dst_ports", ">=", 20), Condition("rejected_ratio", ">=", 0.5)),
         'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SCAN-001 SYN port scan"; flags:S; '
         'detection_filter:track by_src, count 20, seconds 10; sid:1000001;)'),
    Rule("SCAN-002", "Host sweep (horizontal scan)", "portscan", "medium",
         (Condition("n_dst_ips", ">=", 20), Condition("rejected_ratio", ">=", 0.5)),
         'alert ip any any -> $HOME_NET any (msg:"SCAN-002 host sweep"; '
         'detection_filter:track by_src, count 20, seconds 10; sid:1000002;)'),
    Rule("DOS-001", "TCP SYN flood from source", "dos", "high",
         (Condition("syn_count", ">=", 100), Condition("handshake_completion", "<=", 0.2),
          Condition("max_conn_same_service", ">=", 50)),
         'alert tcp any any -> $HOME_NET any (msg:"DOS-001 SYN flood"; flags:S; flow:stateless; '
         'detection_filter:track by_src, count 100, seconds 10; sid:1000003;)'),
    Rule("BF-001", "Brute force on an authentication service (SSH/FTP/Telnet/RDP/SMB)", "bruteforce", "medium",
         (Condition("auth_service_conns", ">=", 10), Condition("max_conn_same_service", ">=", 10),
          Condition("mean_flow_duration", "<=", 5.0)),
         'alert tcp any any -> $HOME_NET 22 (msg:"BF-001 SSH brute force"; flags:S; '
         'detection_filter:track by_src, count 10, seconds 10; sid:1000004;)'),
    Rule("BF-002", "Repeated login failures in clear-text protocol", "bruteforce", "medium",
         (Condition("auth_failures", ">=", 5),),
         'alert tcp $HOME_NET 21 -> any any (msg:"BF-002 FTP login failed"; content:"530 "; depth:4; '
         'detection_filter:track by_dst, count 5, seconds 10; sid:1000005;)'),
    Rule("ARP-001", "ARP IP-to-MAC binding changed (spoofing / MITM)", "arpspoof", "high",
         (Condition("arp_ip_mac_changes", ">=", 1),),
         '# arpspoof preprocessor equivalent: IP already bound to a different MAC (sid 112:2 style)'),
    Rule("ARP-002", "Unsolicited ARP replies (poisoning)", "arpspoof", "medium",
         (Condition("arp_unsolicited", ">=", 5),),
         '# arpspoof preprocessor equivalent: ARP replies with no matching request, >=5 in 10 s'),
)

#: Victim-centric rule, evaluated on (destination, port, window) so spoofed-source floods are still seen.
DOS002 = {"rule_id": "DOS-002", "name": "SYN flood against one service (victim view)", "label": "dos",
          "severity": "high", "min_syn": 300, "max_completion": 0.2}


def evaluate_rules(windows: pd.DataFrame) -> list[list[dict]]:
    """List of matched-rule explanations for every window (empty list = no rule fired)."""
    out: list[list[dict]] = []
    for _, row in windows.iterrows():
        out.append([m for r in RULES if (m := r.match(row)) is not None])
    return out


def evaluate_victims(victims: pd.DataFrame) -> list[dict]:
    """DOS-002: many SYNs to one destination service with almost no completed handshakes."""
    alerts: list[dict] = []
    if victims is None or victims.empty:
        return alerts
    for _, v in victims.iterrows():
        completion = v["completed"] / v["syn_in"] if v["syn_in"] else 1.0
        if v["syn_in"] >= DOS002["min_syn"] and completion <= DOS002["max_completion"]:
            alerts.append({**{k: DOS002[k] for k in ("rule_id", "name", "label", "severity")},
                           "target": f'{v["dst"]}:{int(v["dport"])}', "window_start": float(v["window_start"]),
                           "syn_in": int(v["syn_in"]), "completion": round(float(completion), 3),
                           "n_srcs": int(v["n_srcs"]),
                           "why": f'{int(v["syn_in"])} SYNs in 10 s >= {DOS002["min_syn"]} and handshake completion '
                                  f'{completion:.2f} <= {DOS002["max_completion"]} from {int(v["n_srcs"])} sources'})
    return alerts
