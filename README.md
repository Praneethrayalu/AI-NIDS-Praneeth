# AI-Driven Network Traffic Analysis and Intrusion Detection System

**Author:** Praneeth Rayalu Repalle (B.Tech CSE, Cyber Security, LPU, 2026)
**For:** MegaMinds IT Services, Cybersecurity & Network Security Research Intern, Round 1 take-home

A working prototype that ingests packet captures, extracts flow and time-window features, and detects
intrusions with a **hybrid engine**: Snort-style threshold rules (8 rules), a supervised **RandomForest** and an
unsupervised **IsolationForest**. Every alert says *what* was flagged, *why* (rule threshold vs observed value,
top feature contributions, anomaly score), *how confident* the engine is and *how severe* it is. It ships with a CLI,
a Streamlit dashboard, five reproducible attack scenarios, and an honest evaluation that includes a case it gets wrong.

![architecture](results/figures/architecture.png)

```
 pcap/pcapng ──► header parser ──► bidirectional flows ──► host x 10 s windows (32 features)
 (scapy-made        (struct, works      (5-tuple, idle        + victim view (dst:port)
  or real capture)   with snaplen)       timeout, TCP state)   + ARP IP->MAC baseline
                                                │
                     ┌──────────────────────────┼──────────────────────────┐
                     ▼                          ▼                          ▼
              Rule layer (8 rules)      RandomForest (5 classes)   IsolationForest (benign-only)
              SCAN/DOS/BF/ARP           p(class)                   anomaly score
                     └──────────────► Fusion + explanation ◄───────────────┘
                                   verdict, confidence, severity, why
                                                │
                       CLI table + JSON/CSV  ◄──┴──►  Streamlit dashboard
```

## Repository layout

| Path | What it does |
|---|---|
| `traffic/generate.py` | Seeded scapy generator: 5 scenario pcaps + randomised training pcaps + ground-truth JSON |
| `features/extractor.py` | pcap reader, header parser, flow table, per-window features, victim view, ARP baseline, labelling |
| `detection/rules.py` | Snort-style threshold rules with readable ids (SCAN-001 ... ARP-002, DOS-002 victim view) |
| `detection/ml.py` | RandomForest + IsolationForest, benign baseline, per-sample feature contributions |
| `detection/engine.py` | Fusion of the three layers, confidence, severity, explanation text |
| `detection/train.py` | Builds the training table, grouped cross-validation, fits and saves the models |
| `nids/cli.py` | `python -m nids generate / train / analyze / evaluate` |
| `app.py` | Streamlit dashboard |
| `evaluation/evaluate.py` | Metrics, confusion matrices, TP/FP/FN examples, throughput, DoS impact, figures |
| `tests/` | pytest suite (6 tests) |
| `data/pcaps/`, `data/ground_truth/` | The 5 scenario captures and their labels (committed, 19 MB) |
| `data/train_features.csv.gz` | Cached training table (the 12 training pcaps are regenerable, not committed) |
| `models/nids_models.joblib` | Trained models |
| `results/` | `metrics.json`, `metrics_summary.md`, `alerts/*.json|csv`, `figures/*.png` |
| `docs/Technical_Report.pdf` | The technical report |
| `docs/screenshots/` | Screenshots of real CLI, test, evaluation and dashboard runs (see Screenshots below) |

## Setup

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
Python 3.10+ (tested on 3.11). No root, no live interface and no internet access are needed: everything runs offline on pcaps.
If loading the saved model warns about a different scikit-learn version, retrain it (about 20 s from the cached table): `python -m nids train`.

## Quick start (uses the committed data and model)

```bash
python -m nids analyze --pcap data/pcaps/s2_portscan.pcap                       # table + explanations
python -m nids analyze --pcap data/pcaps/s4_bruteforce_arp.pcap --json out.json --csv out.csv --verbose
streamlit run app.py                                                             # dashboard
python -m pytest -q tests
```

## The five mandatory scenarios

| # | Command | What is in the capture | Expected result |
|---|---|---|---|
| 1 | `python -m nids analyze --pcap data/pcaps/s1_benign.pcap` | 120 s of 15 workstations: DNS, HTTP, TLS-like 443, ICMP, a long admin SSH session, normal ARP | 0 alerts |
| 2 | `python -m nids analyze --pcap data/pcaps/s2_portscan.pcap` | Benign background + SYN scan of 999 ports on the server (~230 probes/s), then a slow 60-port scan of a workstation (~1.5 probes/s) | SCAN-001 on the fast scan; most windows of the slow part are below the rule threshold and are caught only by the RandomForest |
| 3 | `python -m nids analyze --pcap data/pcaps/s3_dos.pcap` | SYN flood from 6 bots on the web server (~1,300 pps for 30 s) and legitimate clients suffering | DOS-001 on every bot window, DOS-002 victim alert, visible service impact |
| 4 | `python -m nids analyze --pcap data/pcaps/s4_bruteforce_arp.pcap` | SSH brute force (225 attempts), FTP brute force with `530 Login incorrect` replies (60 attempts), ARP poisoning of 3 victims | BF-001/BF-002 and ARP-001/ARP-002 alerts, attacker MAC named |
| 5 | `python -m nids analyze --pcap data/pcaps/s5_ambiguous.pcap` | Low-and-slow scan (1 probe every ~12 s) + a benign, bursty rsync backup (12 connections/s) | Imperfect on purpose: the scan only gets **low-severity** alerts at p=0.51, and the backup is flagged as an anomaly (false positive) |

## Reproduce everything from scratch

```bash
./run_all.sh
# or step by step:
python -m nids generate --seed 42 --train 3   # data/pcaps, data/ground_truth, data/train (about 8 min, scapy is slow)
python -m nids train --rebuild                # data/train_features.csv.gz, models/, results/training_report.json
python -m nids evaluate                       # results/metrics.json, metrics_summary.md, alerts/, figures/
python -m evaluation.architecture             # results/figures/architecture.png
```
The generator is fully seeded: the same seed gives byte-identical pcaps (checked with md5sum).
The **training captures use different seeds, attacker addresses and attack rates** from the test scenarios, and
Scenario 5 is never seen in training.

## Data: why synthetic captures

CICIDS2017 is many gigabytes, labelled per flow by CICFlowMeter, and has known labelling artefacts. Generating
traffic with scapy gives full control and exact ground truth (attacker, interval, attack type), keeps the repository
small, and makes every number reproducible. Captures are written like `tcpdump -s 96`: headers plus the first payload
bytes, with the true packet length kept in each record. That is enough for flow features and for the FTP `530` check,
and it keeps the five pcaps at 19 MB. Any real `.pcap`/`.pcapng` can be analysed the same way.

Simulated topology: a 192.168.10.0/24 LAN behind gateway 192.168.10.1, a server 192.168.10.50 (HTTP, HTTPS, SSH, FTP),
a backup server .60, workstations .10-.29, internal attackers (.66, .77, .88, .99) and external attackers in 203.0.113.0/24.

## Features (per source host per 10 s window)

* **Volume and rate:** packets, bytes, packet rate, byte rate, mean packet size
* **Protocol mix:** fraction of TCP / UDP / ICMP / ARP
* **TCP flags:** SYN count, SYN-ACKs sent, RSTs, FINs, SYN ratio, SYN/ACK ratio
* **Flows started by the host:** count and connection rate, unique destination IPs, **unique destination ports**,
  max connections to one service, mean flow duration / packets / bytes, share of short flows,
  handshake completion ratio, rejected ratio, connections to authentication ports, login failures seen in replies
* **ARP:** requests, replies, unsolicited replies, **IP-to-MAC binding changes** against a baseline learned from
  which MAC actually sources each LAN IP's traffic

Why windows and not single flows: one SYN probe of a scan is indistinguishable from one failed connection. Grouping
everything a source did in a window makes scans, floods and brute force visible, while every flow statistic is kept
as a mean or ratio. A separate **victim view** per destination:port catches floods with spoofed sources that no
single source window would show.

## Detection

**Rules** (`detection/rules.py`, Snort-style signature next to each):

| id | name | condition per source per 10 s |
|---|---|---|
| SCAN-001 | TCP SYN port scan | unique dst ports >= 20 and rejected ratio >= 0.5 |
| SCAN-002 | Host sweep | unique dst IPs >= 20 and rejected ratio >= 0.5 |
| DOS-001 | SYN flood from source | SYNs >= 100, handshake completion <= 0.2, >= 50 connections to one service |
| DOS-002 | SYN flood, victim view | >= 300 SYNs to one dst:port, completion <= 0.2 (any number of sources) |
| BF-001 | Brute force on an auth service | >= 10 connections to ports 21/22/23/445/3389, >= 10 to one service, mean duration <= 5 s |
| BF-002 | Clear-text login failures | >= 5 `530`/`Login incorrect` replies |
| ARP-001 | ARP binding changed | an ARP message binds a known IP to a different MAC |
| ARP-002 | Unsolicited ARP replies | >= 5 replies with no matching request |

**ML:** RandomForest (150 trees, depth 12, balanced class weights) on log1p features, 5 classes; IsolationForest
(200 trees) fitted on benign windows only, alert threshold = 0.2nd percentile of benign training scores.

**Fusion:** rule fired → rule class (confidence combined with the RF when it agrees); else RF attack class with
p >= 0.5; else IsolationForest anomaly → `anomaly` (low severity, for triage); else benign.
**Severity:** DoS and ARP spoofing are high; scans and brute force are medium; anomalies are low. A one-layer detection
with confidence < 0.6 drops one level, and a brute force confirmed by both rules and RF rises to high.

**Explanation per alert:** source, destinations, ports, window; each matched rule with observed value vs threshold;
RF class probabilities; top-3 features ranked by RF importance x deviation from the benign median; IsolationForest
score vs threshold. Example (Scenario 4):

```
EVT-0007 192.168.10.77 -> 192.168.10.50 port 21, 10:01:10-10:01:20 UTC  verdict=bruteforce  severity=high  confidence=0.99
  BF-001: auth_service_conns=17 >= 10 and max_conn_same_service=17 >= 10 and mean_flow_duration=0.912 <= 5
  BF-002: auth_failures=17 >= 5
  RF: bruteforce p=1.00
  top features: auth_service_conns=17 (benign median 0), mean_flow_duration=0.912 (benign median 0), syn_ack_ratio=0.25 (benign median 0)
  IsolationForest score -0.162 (threshold -0.161) ANOMALOUS
```

## Results (real output of `python -m nids evaluate`)

Unit = host-window (one source in one 10 s window). Positive = malicious.

| Scenario | windows | malicious | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| S1 Benign | 566 | 0 | 0 | 0 | 0 | 566 | 1.000 | n/a | n/a | 1.000 |
| S2 Port scan | 515 | 6 | 6 | 1 | 0 | 508 | 0.857 | 1.000 | 0.923 | 0.998 |
| S3 SYN flood | 500 | 18 | 18 | 3 | 0 | 479 | 0.857 | 1.000 | 0.923 | 0.994 |
| S4 Brute force + ARP | 599 | 12 | 12 | 1 | 0 | 586 | 0.923 | 1.000 | 0.960 | 0.998 |
| S5 Ambiguous | 1020 | 17 | 17 | 4 | 0 | 999 | 0.809 | 1.000 | 0.895 | 0.996 |
| **Overall** | 3200 | 53 | 53 | 9 | 0 | 3138 | 0.855 | 1.000 | 0.922 | 0.997 |

| Layer | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| rules only | 31 | 0 | 22 | 1.000 | 0.585 | 0.738 |
| RandomForest only | 49 | 1 | 4 | 0.980 | 0.924 | 0.952 |
| IsolationForest only | 47 | 9 | 6 | 0.839 | 0.887 | 0.862 |
| hybrid (final) | 53 | 9 | 0 | 0.855 | 1.000 | 0.922 |
| hybrid, medium+ severity | 35 | 1 | 18 | 0.972 | 0.660 | 0.786 |

| Attack | windows | flagged | detected | right class | time to detect (s) |
|---|---|---|---|---|---|
| SYN scan of 999 ports on 192.168.10.50 at ~230 probes/s | 6 | 6 | True | True | 10.0 |
| SYN scan of 60 ports on 192.168.10.12 at ~2 probes/s | 6 | 6 | True | True | 0.5 |
| SYN flood on 192.168.10.50:80 at ~1300 pps from 6 bots | 18 | 18 | True | True | 10.0 |
| SSH brute force, 225 attempts on 192.168.10.50:22 | 5 | 5 | True | True | 10.0 |
| FTP brute force, 60 attempts on 192.168.10.50:21 | 3 | 3 | True | True | 10.0 |
| ARP poisoning of 3 victims (gateway 192.168.10.1 -> 02:00:00:00:00:63) | 4 | 4 | True | True | 10.0 |
| low-and-slow SYN scan, 17 ports, one probe every ~12 s | 17 | 17 | True | True | 10.0 |

| Scenario | packets | extract s | detect s | packets/s | ms/window | x real time |
|---|---|---|---|---|---|---|
| S1 Benign | 29251 | 0.589 | 0.17 | 38569 | 0.3 | 157.3 |
| S2 Port scan | 27264 | 0.437 | 1.207 | 16586 | 2.344 | 72.9 |
| S3 SYN flood | 73449 | 1.413 | 3.002 | 16635 | 6.005 | 27.2 |
| S4 Brute force + ARP | 30293 | 0.471 | 1.896 | 12797 | 3.165 | 64.6 |
| S5 Ambiguous | 47350 | 0.862 | 2.999 | 12263 | 2.94 | 93.4 |

DoS impact measured in the Scenario 3 capture (legitimate clients of the web server): median SYN→SYN/ACK time 1.0 ms before the flood vs 173 ms during it; unanswered SYNs 0 % before vs 39.2 % during. The generator models the overloaded server, so this shows the analysis works, not a real server measurement.


Figures in `results/figures/`: `confusion_per_scenario.png`, `confusion_overall_multiclass.png`, `ablation_layers.png`,
`throughput.png`, `s3_dos_timeline.png`, `feature_importance.png`, `architecture.png`.

**Reading the numbers honestly**
* Recall is 1.0 because the attacks are synthetic and cleanly separable. Real traffic will be messier; treat these as
  an upper bound.
* Accuracy is inflated by thousands of easy benign windows (e.g. external web servers answering clients).
  Precision, recall and the FP count are the meaningful numbers.
* Rules alone: 0 false positives but they miss 22 of 53 malicious windows (slow scans, flood tail windows).
  The RandomForest fills those gaps, and the IsolationForest adds catches but brings all 9 false positives.
* Scenario 5 shows the limitation: the low-and-slow scan is "detected" only at low severity (RF p=0.51 or anomaly
  score), and the same evidence (one rejected SYN) also fires on legitimate clients whose SYNs went unanswered during
  the flood in Scenario 3. If you only page an analyst on medium+ severity, the slow scan is missed entirely
  (recall 0.66 for that operating point). The benign backup burst produces 4 low-severity false positives.
* The first version set the IsolationForest threshold at the 1st percentile; that gave 42 false positives on these
  test windows, so it was tightened to the 0.2nd percentile (chosen from the training score distribution).
* Timing is measured on a shared 4-vCPU cloud box and varies with load; rates are offline batch rates, not inline.

## Screenshots

All of these are real runs of the code in this repository (CLI output captured from the terminal, dashboard captured
from `streamlit run app.py`). Timing numbers vary a little from run to run with machine load.

### CLI: the five scenarios

**Scenario 1, benign traffic:** `python -m nids analyze --pcap data/pcaps/s1_benign.pcap` gives 0 alerts.

![Scenario 1](docs/screenshots/01_s1_benign_cli.png)

**Scenario 2, port scan:** SCAN-001 on the fast scan; the slow part of the scan is caught by the RandomForest.

![Scenario 2](docs/screenshots/02_s2_portscan_cli.png)

**Scenario 3, SYN flood DoS:** DOS-001 on every bot window plus the DOS-002 victim view.

![Scenario 3](docs/screenshots/03_s3_dos_cli.png)

**Scenario 4, SSH/FTP brute force + ARP spoofing:** BF-001/BF-002 and ARP-001/ARP-002, attacker MAC named.

![Scenario 4](docs/screenshots/04_s4_bruteforce_arp_cli.png)

**Scenario 5, ambiguous case:** the low-and-slow scan only gets low-severity alerts (p=0.51) and the backup burst is flagged as an anomaly.

![Scenario 5](docs/screenshots/05_s5_ambiguous_cli.png)

### Tests and evaluation

![pytest](docs/screenshots/06_tests_pytest.png)

![evaluation](docs/screenshots/07_evaluation_cli.png)

### Streamlit dashboard

Start screen:

![dashboard](docs/screenshots/08_dashboard_home.png)

Scenario 4 alerts table with the summary metrics:

![alerts](docs/screenshots/09_dashboard_s4_alerts_table.png)

One alert explained: rule matched with observed value vs threshold, the Snort-style signature, RandomForest class
probabilities, top feature contributions and the IsolationForest score, followed by the ARP binding changes:

![explanation](docs/screenshots/10_dashboard_s4_alert_explanation.png)

Charts for Scenario 3 (traffic vs flagged packets per window, alerts by verdict and severity) and Scenario 2:

![charts s3](docs/screenshots/11_dashboard_s3_dos_charts.png)

![charts s2](docs/screenshots/12_dashboard_s2_portscan_charts.png)

### Evaluation figures

![confusion per scenario](results/figures/confusion_per_scenario.png)

![confusion overall](results/figures/confusion_overall_multiclass.png)

![ablation](results/figures/ablation_layers.png)

![throughput](results/figures/throughput.png)

![DoS timeline](results/figures/s3_dos_timeline.png)

![feature importance](results/figures/feature_importance.png)

## Limitations

* Synthetic traffic: clean, regular patterns; no real application noise, NAT, retransmission storms or encrypted-protocol variety.
* Small training set (19 scan, 51 DoS, 20 brute-force, 12 ARP windows); the RandomForest is close to memorising the generator.
* Fixed 10 s tumbling windows: anything slower than one event per window (Scenario 5) is invisible to rules,
  and detection waits for the window to close (time to detect ~10 s).
* Per-source keys: spoofed-source floods need the victim view; distributed scans across many sources would evade per-source rules.
* ARP baseline is learned from the whole capture (offline). Live use needs a trusted table (DHCP snooping, static entries).
* Payload checks only cover clear-text protocols; SSH brute force is detected from behaviour alone.
* Python, single process: tens of thousands of packets/s offline, far below line rate on a busy link.

## Future work

Multi-scale windows (10 s / 5 min / 1 h) with per-source state for low-and-slow attacks; incident correlation across
windows; Zeek or CICFlowMeter features and evaluation on CICIDS2017/UNSW-NB15 to test generalisation; SHAP values
instead of importance x deviation; streaming capture (AF_PACKET / PF_RING) with a compiled flow meter; analyst feedback
loop to retrain and suppress known-benign jobs (e.g. an allow-list for the backup window); export of rules to real Snort/Suricata.

## Ethics

All traffic is generated locally in pcaps; nothing is sent on a network. The attack generators exist only to produce labelled test data.

## Submission

- Technical report: [`submission/Technical_Report.pdf`](submission/Technical_Report.pdf)
- Demo video (1080p, ~9:40): [`submission/Demo_Video_Praneeth.mp4`](submission/Demo_Video_Praneeth.mp4), also on Google Drive: https://drive.google.com/file/d/1EUyVD4Eq_UhL7N0etnT-ng8nBd4hp63T/view?usp=sharing

Author: Praneeth Rayalu Repalle
