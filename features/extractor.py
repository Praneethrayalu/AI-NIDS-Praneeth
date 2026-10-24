"""Flow-based, time-windowed feature extraction from pcap/pcapng.

Pipeline::

    pcap -> packet parser (struct, header-only) -> bidirectional flow table (5-tuple, idle timeout)
         -> per (source entity, 10 s window) aggregation  -> feature vector per host-window
         -> per (destination, port, window) aggregation   -> victim view (spoofed-source floods)

The unit that is classified is a *host-window*: everything one source did in one time window.
Single flows are a poor unit for scans and floods (one SYN probe looks like any failed connection);
aggregating the flows a source opened in a window makes the behaviour visible while every flow-level
statistic (duration, bytes, packets, handshake outcome) is kept as a mean/ratio feature.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import dpkt  # only for robust pcap / pcapng reading
import pandas as pd

WINDOW_SECONDS = 10.0
FLOW_IDLE_TIMEOUT = 60.0
AUTH_PORTS = {21, 22, 23, 3389, 445}
AUTH_FAIL_MARKERS = (b"530 ", b"Login incorrect", b"Authentication failed", b"Permission denied")

FEATURE_COLUMNS: list[str] = [
    # packet-level (what the source sent in the window)
    "pkts", "bytes", "pkt_rate", "byte_rate", "mean_pkt_size",
    "frac_tcp", "frac_udp", "frac_icmp", "frac_arp",
    "syn_count", "synack_sent", "rst_sent", "fin_sent", "syn_ratio", "syn_ack_ratio",
    # flow-level (flows the source initiated in the window)
    "n_flows", "conn_rate", "n_dst_ips", "n_dst_ports", "max_conn_same_service",
    "mean_flow_duration", "mean_flow_pkts", "mean_flow_bytes", "frac_short_flows",
    "handshake_completion", "rejected_ratio", "auth_service_conns", "auth_failures",
    # ARP behaviour
    "arp_requests", "arp_replies", "arp_unsolicited", "arp_ip_mac_changes",
]


@dataclass
class Packet:
    """Minimal parsed view of one frame (header fields only)."""

    ts: float
    wirelen: int
    src_mac: str
    dst_mac: str
    kind: str  # tcp | udp | icmp | arp | other
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    flags: int = 0
    payload: bytes = b""
    arp_op: int = 0
    arp_sha: str = ""
    arp_spa: str = ""
    arp_tpa: str = ""


@dataclass
class Flow:
    """Bidirectional flow; the initiator is the sender of the first packet."""

    proto: str
    src: str
    dst: str
    sport: int
    dport: int
    start: float
    last: float
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn: bool = False
    synack: bool = False
    completed: bool = False
    rejected: bool = False
    closed: bool = False
    auth_fail: int = 0
    synack_ts: float = -1.0

    @property
    def duration(self) -> float:
        return self.last - self.start

    @property
    def pkts(self) -> int:
        return self.fwd_pkts + self.bwd_pkts

    @property
    def nbytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_frame(ts: float, buf: bytes, wirelen: int) -> Packet | None:
    """Parse Ethernet/IPv4/TCP/UDP/ICMP/ARP headers with struct (tolerates snaplen truncation)."""
    if len(buf) < 14:
        return None
    etype = struct.unpack("!H", buf[12:14])[0]
    off = 14
    if etype == 0x8100 and len(buf) >= 18:  # 802.1Q
        etype = struct.unpack("!H", buf[16:18])[0]
        off = 18
    p = Packet(ts=ts, wirelen=wirelen, src_mac=_mac(buf[6:12]), dst_mac=_mac(buf[0:6]), kind="other")
    if etype == 0x0806 and len(buf) >= off + 28:
        a = buf[off:off + 28]
        p.kind, p.arp_op = "arp", struct.unpack("!H", a[6:8])[0]
        p.arp_sha, p.arp_spa = _mac(a[8:14]), socket.inet_ntoa(a[14:18])
        p.arp_tpa = socket.inet_ntoa(a[24:28])
        return p
    if etype != 0x0800 or len(buf) < off + 20:
        return p
    ihl = (buf[off] & 0x0F) * 4
    total_len, proto = struct.unpack("!H", buf[off + 2:off + 4])[0], buf[off + 9]
    p.src, p.dst = socket.inet_ntoa(buf[off + 12:off + 16]), socket.inet_ntoa(buf[off + 16:off + 20])
    p.wirelen = max(total_len + 14, wirelen) if total_len else wirelen
    l4 = off + ihl
    if proto == 6 and len(buf) >= l4 + 14:
        p.kind = "tcp"
        p.sport, p.dport = struct.unpack("!HH", buf[l4:l4 + 4])
        doff = (buf[l4 + 12] >> 4) * 4
        p.flags = buf[l4 + 13]
        p.payload = buf[l4 + doff:]
    elif proto == 17 and len(buf) >= l4 + 8:
        p.kind = "udp"
        p.sport, p.dport = struct.unpack("!HH", buf[l4:l4 + 4])
        p.payload = buf[l4 + 8:]
    elif proto == 1:
        p.kind = "icmp"
    return p


def read_pcap(path: str | Path) -> list[Packet]:
    """Read every frame of a pcap or pcapng file into Packet objects."""
    out: list[Packet] = []
    with open(path, "rb") as fh:
        reader = dpkt.pcap.UniversalReader(fh)
        for ts, buf in reader:
            pkt = parse_frame(float(ts), bytes(buf), len(buf))
            if pkt is not None:
                out.append(pkt)
    out.sort(key=lambda p: p.ts)
    return out


FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_private(ip: str) -> bool:
    """RFC 1918 only (ipaddress.is_private also includes documentation ranges such as 203.0.113.0/24)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _RFC1918)


@dataclass
class Extraction:
    """Everything the detector and the dashboard need from one capture."""

    windows: pd.DataFrame
    flows: pd.DataFrame
    victims: pd.DataFrame
    arp_events: list[dict] = field(default_factory=list)
    n_packets: int = 0
    duration: float = 0.0
    seconds: float = 0.0  # wall time spent extracting


def build_flows(packets: list[Packet]) -> list[Flow]:
    """Assemble bidirectional flows with handshake/teardown state and FTP auth-failure counting."""
    active: dict[tuple, Flow] = {}
    done: list[Flow] = []
    for p in packets:
        if p.kind not in ("tcp", "udp", "icmp"):
            continue
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (p.kind,) + (a + b if a <= b else b + a)
        f = active.get(key)
        new_syn = p.kind == "tcp" and p.flags & SYN and not p.flags & ACK
        if f is not None and (p.ts - f.last > FLOW_IDLE_TIMEOUT or (new_syn and (f.closed or f.completed or f.synack))):
            done.append(active.pop(key))
            f = None
        if f is None:
            f = Flow(p.kind, p.src, p.dst, p.sport, p.dport, p.ts, p.ts)
            active[key] = f
        f.last = p.ts
        fwd = p.src == f.src and p.sport == f.sport
        if fwd:
            f.fwd_pkts += 1
            f.fwd_bytes += p.wirelen
        else:
            f.bwd_pkts += 1
            f.bwd_bytes += p.wirelen
        if p.kind == "tcp":
            if fwd and p.flags & SYN and not p.flags & ACK:
                f.syn = True
            elif not fwd and p.flags & SYN and p.flags & ACK:
                if not f.synack:
                    f.synack_ts = p.ts
                f.synack = True
            elif fwd and f.synack and p.flags & ACK and not p.flags & RST:
                f.completed = True
            if p.flags & RST:
                f.closed = True
                if not fwd and not f.completed:
                    f.rejected = True
            if p.flags & FIN:
                f.closed = True
            if not fwd and p.payload and any(m in p.payload[:40] for m in AUTH_FAIL_MARKERS):
                f.auth_fail += 1
    done.extend(active.values())
    return done


def extract(pcap: str | Path, window: float = WINDOW_SECONDS) -> Extraction:
    """Run the full extraction for one capture."""
    import time

    t0 = time.perf_counter()
    packets = read_pcap(pcap)
    flows = build_flows(packets)

    # MAC -> IP learned from IP traffic of private hosts (used to attribute ARP frames to a host)
    seen: dict[str, Counter] = defaultdict(Counter)
    for p in packets:
        if p.kind in ("tcp", "udp", "icmp") and _is_private(p.src):
            seen[p.src_mac][p.src] += 1
    mac2ip = {m: c.most_common(1)[0][0] for m, c in seen.items()}
    # Trusted IP -> MAC baseline: the MAC that actually sources each LAN IP's IP traffic (majority vote over the
    # capture).  ARP claims are judged against it, so the verdict does not depend on whether the attacker's
    # first forged reply happens to arrive before the legitimate one (the weakness of first-seen tables).
    ip_macs: dict[str, Counter] = defaultdict(Counter)
    for m, c in seen.items():
        for ip, n in c.items():
            ip_macs[ip][m] += n
    trusted = {ip: c.most_common(1)[0][0] for ip, c in ip_macs.items()}

    agg: dict[tuple[str, float], dict] = defaultdict(lambda: defaultdict(float))
    ports: dict[tuple[str, float], set] = defaultdict(set)
    dsts: dict[tuple[str, float], set] = defaultdict(set)
    services: dict[tuple[str, float], Counter] = defaultdict(Counter)
    durs: dict[tuple[str, float], list] = defaultdict(list)
    victim: dict[tuple[str, int, float], dict] = defaultdict(lambda: defaultdict(float))
    victim_srcs: dict[tuple[str, int, float], set] = defaultdict(set)

    binding: dict[str, str] = dict(trusted)  # IP -> MAC; unknown IPs fall back to first-seen (arpwatch style)
    pending_req: dict[tuple[str, str], float] = {}
    arp_events: list[dict] = []
    for p in packets:
        wstart = (p.ts // window) * window
        if p.kind == "arp":
            ent = mac2ip.get(p.arp_sha, p.arp_spa)
            k = (ent, wstart)
            a = agg[k]
            a["pkts"] += 1
            a["bytes"] += p.wirelen
            a["n_arp"] += 1
            if p.arp_op == 1:
                a["arp_requests"] += 1
                pending_req[(p.arp_spa, p.arp_tpa)] = p.ts
            elif p.arp_op == 2:
                a["arp_replies"] += 1
                asked = pending_req.get((p.arp_tpa, p.arp_spa))
                if asked is None or p.ts - asked > 5.0:
                    a["arp_unsolicited"] += 1
            old = binding.get(p.arp_spa)
            if old is None:
                binding[p.arp_spa] = p.arp_sha
            elif old != p.arp_sha:
                a["arp_ip_mac_changes"] += 1
                if len(arp_events) < 500:
                    arp_events.append({"ts": p.ts, "ip": p.arp_spa, "known_mac": old, "claimed_mac": p.arp_sha,
                                       "sender": ent, "op": "reply" if p.arp_op == 2 else "request"})
            continue
        if p.kind == "other":
            continue
        k = (p.src, wstart)
        a = agg[k]
        a["pkts"] += 1
        a["bytes"] += p.wirelen
        a["n_" + p.kind] += 1
        if p.kind == "tcp":
            if p.flags & SYN and not p.flags & ACK:
                a["syn_count"] += 1
                vk = (p.dst, p.dport, wstart)
                victim[vk]["syn_in"] += 1
                victim_srcs[vk].add(p.src)
            if p.flags & SYN and p.flags & ACK:
                a["synack_sent"] += 1
            if p.flags & ACK:
                a["ack_count"] += 1
            if p.flags & RST:
                a["rst_sent"] += 1
            if p.flags & FIN:
                a["fin_sent"] += 1

    for f in flows:
        wstart = (f.start // window) * window
        k = (f.src, wstart)
        a = agg[k]
        a["n_flows"] += 1
        dsts[k].add(f.dst)
        if f.proto in ("tcp", "udp"):
            ports[k].add(f.dport)
            services[k][(f.dst, f.dport)] += 1
        durs[k].append(f.duration)
        a["sum_flow_pkts"] += f.pkts
        a["sum_flow_bytes"] += f.nbytes
        if f.pkts <= 4:
            a["short_flows"] += 1
        if f.proto == "tcp":
            a["tcp_flows"] += 1
            a["completed"] += f.completed
            a["rejected"] += f.rejected or (f.syn and not f.synack)
            if f.dport in AUTH_PORTS:
                a["auth_service_conns"] += 1
            a["auth_failures"] += f.auth_fail
            if f.syn:
                victim[(f.dst, f.dport, wstart)]["completed"] += f.completed

    rows = []
    for (ent, ws), a in agg.items():
        pk = max(a["pkts"], 1.0)
        tcp = a["n_tcp"]
        nf = a["n_flows"]
        d = durs.get((ent, ws), [])
        rows.append({
            "entity": ent, "window_start": ws, "window_end": ws + window,
            "pkts": a["pkts"], "bytes": a["bytes"], "pkt_rate": a["pkts"] / window, "byte_rate": a["bytes"] / window,
            "mean_pkt_size": a["bytes"] / pk,
            "frac_tcp": tcp / pk, "frac_udp": a["n_udp"] / pk, "frac_icmp": a["n_icmp"] / pk, "frac_arp": a["n_arp"] / pk,
            "syn_count": a["syn_count"], "synack_sent": a["synack_sent"], "rst_sent": a["rst_sent"], "fin_sent": a["fin_sent"],
            "syn_ratio": a["syn_count"] / tcp if tcp else 0.0,
            "syn_ack_ratio": a["syn_count"] / (a["ack_count"] + 1.0),
            "n_flows": nf, "conn_rate": nf / window,
            "n_dst_ips": len(dsts.get((ent, ws), ())), "n_dst_ports": len(ports.get((ent, ws), ())),
            "max_conn_same_service": max(services[(ent, ws)].values()) if services.get((ent, ws)) else 0,
            "mean_flow_duration": sum(d) / len(d) if d else 0.0,
            "mean_flow_pkts": a["sum_flow_pkts"] / nf if nf else 0.0,
            "mean_flow_bytes": a["sum_flow_bytes"] / nf if nf else 0.0,
            "frac_short_flows": a["short_flows"] / nf if nf else 0.0,
            "handshake_completion": a["completed"] / a["tcp_flows"] if a["tcp_flows"] else 1.0,
            "rejected_ratio": a["rejected"] / a["tcp_flows"] if a["tcp_flows"] else 0.0,
            "auth_service_conns": a["auth_service_conns"], "auth_failures": a["auth_failures"],
            "arp_requests": a["arp_requests"], "arp_replies": a["arp_replies"],
            "arp_unsolicited": a["arp_unsolicited"], "arp_ip_mac_changes": a["arp_ip_mac_changes"],
            "top_dsts": ",".join(ip for ip, _ in Counter({s[0]: c for s, c in services[(ent, ws)].items()}).most_common(3)) if services.get((ent, ws)) else ",".join(sorted(dsts.get((ent, ws), set()))[:3]),
            "top_ports": ",".join(str(pt) for (_, pt), _ in services[(ent, ws)].most_common(5)) if services.get((ent, ws)) else "",
        })
    windows = pd.DataFrame(rows)
    if not windows.empty:
        windows = windows.sort_values(["window_start", "entity"]).reset_index(drop=True)

    flows_df = pd.DataFrame([{
        "proto": f.proto, "src": f.src, "sport": f.sport, "dst": f.dst, "dport": f.dport, "start": f.start,
        "duration": f.duration, "pkts": f.pkts, "bytes": f.nbytes, "syn": f.syn, "synack": f.synack,
        "completed": f.completed, "rejected": f.rejected, "auth_fail": f.auth_fail,
        "handshake_rtt": (f.synack_ts - f.start) if f.synack_ts >= 0 else None} for f in flows])
    victims = pd.DataFrame([{"dst": d, "dport": pt, "window_start": ws, "syn_in": v["syn_in"],
                             "completed": v["completed"], "n_srcs": len(victim_srcs[(d, pt, ws)])}
                            for (d, pt, ws), v in victim.items() if v["syn_in"] > 0])
    dur = packets[-1].ts - packets[0].ts if packets else 0.0
    return Extraction(windows=windows, flows=flows_df, victims=victims, arp_events=arp_events,
                      n_packets=len(packets), duration=dur, seconds=time.perf_counter() - t0)


def label_windows(windows: pd.DataFrame, truth: dict, slack: float = 1.0) -> pd.Series:
    """Ground-truth label for each host-window from the generator's attack intervals."""
    labels = []
    for ent, ws, we in zip(windows["entity"], windows["window_start"], windows["window_end"]):
        lab = "benign"
        for atk in truth.get("attacks", []):
            if ent in atk["srcs"] and ws <= atk["end"] + slack and we >= atk["start"]:
                lab = atk["label"]
                break
        labels.append(lab)
    return pd.Series(labels, index=windows.index, name="label")
