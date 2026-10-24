"""Streamlit dashboard: pick a pcap, run hybrid detection, inspect explained alerts.

    streamlit run app.py
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from detection.engine import DEFAULT_MODEL, analyze
from detection.ml import Models

ROOT = Path(__file__).resolve().parent
PCAPS = sorted((ROOT / "data" / "pcaps").glob("*.pcap"))
SEV_COLOR = {"high": "#d62728", "medium": "#ff7f0e", "low": "#1f77b4"}

st.set_page_config(page_title="AI-NIDS", layout="wide")
st.title("AI-Driven Network Traffic Analysis & Intrusion Detection")
st.caption("Hybrid engine: Snort-style threshold rules + RandomForest + IsolationForest, with per-alert explanations")


@st.cache_resource
def load_models() -> Models:
    return Models.load(DEFAULT_MODEL)


@st.cache_data(show_spinner=False)
def run(path: str):
    res = analyze(path, load_models())
    return res.windows, res.events, res.victim_alerts, res.arp_events, res.timing


with st.sidebar:
    st.header("Traffic source")
    choice = st.selectbox("Scenario pcap", [p.name for p in PCAPS]) if PCAPS else None
    upload = st.file_uploader("...or upload a .pcap / .pcapng", type=["pcap", "pcapng"])
    go = st.button("Run detection", type="primary")
    min_sev = st.multiselect("Severity filter", ["high", "medium", "low"], default=["high", "medium", "low"])

if go or "result" in st.session_state:
    if go:
        if upload is not None:
            tmp = Path(tempfile.mkdtemp()) / upload.name
            tmp.write_bytes(upload.getvalue())
            path = str(tmp)
        else:
            path = str(ROOT / "data" / "pcaps" / choice)
        with st.spinner("Extracting flows and windows, running detection..."):
            st.session_state["result"] = (path, run(path))
    path, (windows, events, victims, arp_events, timing) = st.session_state["result"]
    events = sorted(events, key=lambda e: ({"high": 0, "medium": 1, "low": 2}[e["severity"]], e["window_start"]))
    st.subheader(Path(path).name)
    c = st.columns(6)
    c[0].metric("Packets", f'{timing["packets"]:,}')
    c[1].metric("Capture span", f'{timing["capture_seconds"]:.0f} s')
    c[2].metric("Host-windows", timing["windows"])
    c[3].metric("Flagged", len(events))
    c[4].metric("Throughput", f'{timing["packets_per_s"]:,.0f} pkt/s')
    c[5].metric("Faster than real time", f'{timing["realtime_factor"]}x')

    ev = pd.DataFrame([{k: e[k] for k in ("event_id", "window_start", "src", "dsts", "dst_ports", "verdict", "severity",
                                          "confidence", "layers", "rule_ids")} for e in events])
    tab1, tab2, tab3 = st.tabs(["Alerts", "Charts", "Raw windows"])
    with tab1:
        if ev.empty:
            st.success("No alerts: every host-window looks benign to all three layers.")
        else:
            ev = ev[ev["severity"].isin(min_sev)]
            st.dataframe(ev, width="stretch", hide_index=True)
            pick = st.selectbox("Inspect event", ev["event_id"].tolist())
            e = next(x for x in events if x["event_id"] == pick)
            st.markdown(f"### {e['event_id']}: <span style='color:{SEV_COLOR[e['severity']]}'>{e['verdict'].upper()} "
                        f"({e['severity']})</span>, confidence {e['confidence']:.2f}", unsafe_allow_html=True)
            st.write(f"**What:** source `{e['src']}` -> {e['dsts'] or '-'} ports {e['dst_ports'] or '-'}, "
                     f"window {e['window_start']} to {e['window_end']} UTC. Layers: `{e['layers']}`")
            st.write("**Why:**")
            for h in e["details"]["rules"]:
                st.write(f"- Rule **{h['rule_id']}** {h['name']}: " + "; ".join(
                    f"{c['feature']} = **{c['observed']:g}** {c['op']} {c['threshold']:g}" for c in h["checks"]))
                st.code(h["snort"], language="text")
            rf = e["details"]["rf"]
            st.write(f"- RandomForest: **{rf['class']}** (p={rf['confidence']:.2f})")
            st.bar_chart(pd.Series(rf["proba"]))
            if e["details"]["top_features"]:
                st.write("- Top feature contributions (RF importance x deviation from benign baseline):")
                st.dataframe(pd.DataFrame(e["details"]["top_features"]), hide_index=True)
            i = e["details"]["iforest"]
            st.write(f"- IsolationForest score {i['score']} vs threshold {i['threshold']}: "
                     f"{'**anomalous**' if i['anomalous'] else 'within benign range'}")
            with st.expander("Raw JSON"):
                st.json(e)
        for v in victims:
            st.warning(f"Victim view {v['rule_id']} on {v['target']} at {v['window_start_iso']}: {v['why']}")
        if arp_events:
            st.error(f"{len(arp_events)} ARP IP->MAC binding changes observed")
            st.dataframe(pd.DataFrame(arp_events).head(20), hide_index=True)
    with tab2:
        w = windows.copy()
        w["t"] = pd.to_datetime(w["window_start"], unit="s")
        st.write("Packets per 10 s window (all hosts) and flagged windows")
        rate = w.groupby("t")["pkts"].sum().rename("packets")
        flagged = w[w["verdict"] != "benign"].groupby("t")["pkts"].sum().rename("flagged packets")
        st.line_chart(pd.concat([rate, flagged], axis=1).fillna(0))
        cc = st.columns(2)
        if not ev.empty:
            cc[0].write("Alerts by verdict")
            cc[0].bar_chart(ev["verdict"].value_counts())
            cc[1].write("Alerts by severity")
            cc[1].bar_chart(ev["severity"].value_counts())
        st.write("Unique destination ports per source (top 10 windows)")
        st.bar_chart(w.nlargest(10, "n_dst_ports").set_index("entity")["n_dst_ports"])
    with tab3:
        st.dataframe(windows, width="stretch")
        st.download_button("Download alerts JSON", json.dumps(events, indent=2, default=str), "alerts.json")
else:
    st.info("Choose a scenario pcap (or upload one) in the sidebar and press **Run detection**.")
