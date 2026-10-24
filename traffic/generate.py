"""Reproducible generator of labelled network traffic scenarios.

Every scenario is written as a classic libpcap file plus a ground-truth JSON
file that lists each malicious activity (attack class, attacker address(es)
and the time interval it was active).  All randomness flows from one seed, so
``python -m traffic.generate --seed 42`` always produces byte-identical pcaps.

Topology (simulated, single /24 LAN behind a gateway)::

    Internet (8.8.8.8 DNS, 93.184.216.0/24 web, 142.250.0.0/16 TLS, 203.0.113.0/24 attackers)
                |
          192.168.10.1  gateway / router (MAC 02:00:00:00:00:01)
                |
    +-----------+-------------------------------------------+
    | 192.168.10.50 server (HTTP 80, HTTPS 443, SSH 22, FTP 21)|
    | 192.168.10.60 backup server (rsync 873)                  |
    | 192.168.10.10-.29 workstations                           |
    | 192.168.10.66/.77/.99 internal attackers (per scenario)  |
    +----------------------------------------------------------+
"""
from __future__ import annotations

import argparse
import json
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw  # type: ignore
from scapy.config import conf

conf.verb = 0

BASE_TS = 1793181600.0  # 2026-10-28 10:00:00 UTC (arbitrary fixed epoch, so pcaps are byte-reproducible)
GATEWAY_IP, GATEWAY_MAC = "192.168.10.1", "02:00:00:00:00:01"
SERVER_IP = "192.168.10.50"
BACKUP_IP = "192.168.10.60"
DNS_IP = "8.8.8.8"
OPEN_PORTS = {21, 22, 80, 443}
SNAPLEN = 96  # headers + first payload bytes, like `tcpdump -s 96`; wire length is kept in each record


def write_pcap(path: Path, records: list[tuple[float, bytes]], snaplen: int = SNAPLEN) -> None:
    """Write a classic libpcap file (Ethernet) with truncated captures but true original lengths."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for ts, raw in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            cap = raw[:snaplen]
            fh.write(struct.pack("<IIII", sec, usec, len(cap), len(raw)))
            fh.write(cap)


def mac_for(ip: str) -> str:
    """Deterministic locally administered MAC for a LAN IP (external IPs sit behind the gateway)."""
    if not ip.startswith("192.168.10."):
        return GATEWAY_MAC
    last = int(ip.rsplit(".", 1)[1])
    return f"02:00:00:00:00:{last:02x}"


@dataclass
class Builder:
    """Accumulates timestamped packets and ground-truth attack intervals."""

    rng: random.Random
    packets: list[tuple[float, bytes]] = field(default_factory=list)
    truth: list[dict] = field(default_factory=list)

    # ---------------------------------------------------------------- helpers
    def add(self, pkt, t: float, src_mac: str | None = None, dst_mac: str | None = None) -> None:
        """Wrap an IP/ARP packet in Ethernet, serialise it and keep it with its timestamp."""
        if not isinstance(pkt, Ether):
            if pkt.haslayer(IP):
                src_mac = src_mac or mac_for(pkt[IP].src)
                dst_mac = dst_mac or mac_for(pkt[IP].dst)
            pkt = Ether(src=src_mac or "02:00:00:00:00:fe", dst=dst_mac or "ff:ff:ff:ff:ff:ff") / pkt
        self.packets.append((BASE_TS + t, bytes(pkt)))

    def label(self, label: str, srcs: Iterable[str], start: float, end: float, note: str) -> None:
        """Record one ground-truth malicious activity."""
        self.truth.append({"label": label, "srcs": sorted(set(srcs)), "start": BASE_TS + start,
                           "end": BASE_TS + end, "note": note})

    def tcp_session(self, t: float, c: str, s: str, dport: int, req: bytes, resp_bytes: int,
                    rtt: float = 0.002, mss: int = 1400, handshake_delay: float | None = None) -> float:
        """Complete TCP session: handshake, request, segmented response, FIN teardown."""
        sport = self.rng.randint(32768, 60999)
        seq_c, seq_s = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        hd = rtt if handshake_delay is None else handshake_delay
        self.add(IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c), t)
        self.add(IP(src=s, dst=c) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1), t + hd / 2)
        t += hd
        self.add(IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1), t)
        if req:
            self.add(IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(req), t + 0.0005)
        t += rtt / 2
        sent = 0
        while sent < resp_bytes:
            n = min(mss, resp_bytes - sent)
            self.add(IP(src=s, dst=c) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s + 1 + sent,
                                           ack=seq_c + 1 + len(req)) / Raw(b"x" * n), t)
            sent += n
            t += 0.0004 + self.rng.random() * 0.0008
            if sent // mss % 4 == 0:
                self.add(IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="A"), t)
        t += rtt / 2
        self.add(IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="FA"), t)
        self.add(IP(src=s, dst=c) / TCP(sport=dport, dport=sport, flags="FA"), t + rtt / 2)
        self.add(IP(src=c, dst=s) / TCP(sport=sport, dport=dport, flags="A"), t + rtt)
        return t + rtt

    # ------------------------------------------------------------ benign mix
    def benign(self, duration: float, clients: list[str], intensity: float = 1.0) -> None:
        """Mixed benign traffic: DNS, HTTP, TLS-like HTTPS, ICMP, a normal SSH session, normal ARP."""
        r = self.rng
        sites = [f"93.184.216.{i}" for i in range(10, 40)]
        tls = [f"142.250.{r.randint(0, 255)}.{r.randint(1, 254)}" for _ in range(25)]
        names = ["example.com", "lpu.in", "github.com", "pypi.org", "news.ycombinator.com", "wikipedia.org"]
        for c in clients:
            t = r.uniform(0, 3)
            while t < duration:
                kind = r.choices(["dns_http", "tls", "intranet", "icmp"], [0.35, 0.40, 0.18, 0.07])[0]
                if kind in ("dns_http", "tls"):
                    qn = r.choice(names)
                    qid = r.randint(0, 65535)
                    sp = r.randint(1024, 65535)
                    self.add(IP(src=c, dst=DNS_IP) / UDP(sport=sp, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qn)), t)
                    dst = r.choice(sites if kind == "dns_http" else tls)
                    self.add(IP(src=DNS_IP, dst=c) / UDP(sport=53, dport=sp) /
                             DNS(id=qid, qr=1, qd=DNSQR(qname=qn), an=DNSRR(rrname=qn, rdata=dst)), t + 0.015)
                    t += 0.02
                    if kind == "dns_http":
                        req = f"GET /{r.randint(1, 999)} HTTP/1.1\r\nHost: {qn}\r\n\r\n".encode()
                        t = self.tcp_session(t, c, dst, 80, req, r.randint(800, 60000), rtt=r.uniform(0.02, 0.06))
                    else:
                        hello = b"\x16\x03\x01" + bytes(r.getrandbits(8) for _ in range(200))
                        t = self.tcp_session(t, c, dst, 443, hello, r.randint(3000, 120000), rtt=r.uniform(0.015, 0.05))
                elif kind == "intranet":
                    port = r.choice([80, 443])
                    t = self.tcp_session(t, c, SERVER_IP, port, b"GET /intranet HTTP/1.1\r\n\r\n", r.randint(500, 20000))
                else:
                    for k in range(4):
                        self.add(IP(src=c, dst=GATEWAY_IP) / ICMP(type=8, id=7, seq=k), t + k)
                        self.add(IP(src=GATEWAY_IP, dst=c) / ICMP(type=0, id=7, seq=k), t + k + 0.001)
                    t += 4
                t += r.expovariate(0.45 * intensity)
        # one long, legitimate interactive SSH session (admin)
        admin = clients[0]
        t, sport = 2.0, 50022
        self.add(IP(src=admin, dst=SERVER_IP) / TCP(sport=sport, dport=22, flags="S"), t)
        self.add(IP(src=SERVER_IP, dst=admin) / TCP(sport=22, dport=sport, flags="SA"), t + 0.001)
        self.add(IP(src=admin, dst=SERVER_IP) / TCP(sport=sport, dport=22, flags="A"), t + 0.002)
        self.add(IP(src=SERVER_IP, dst=admin) / TCP(sport=22, dport=sport, flags="PA") / Raw(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"), t + 0.01)
        while t < duration - 2:
            t += r.expovariate(2.0)
            self.add(IP(src=admin, dst=SERVER_IP) / TCP(sport=sport, dport=22, flags="PA") / Raw(bytes(r.getrandbits(8) for _ in range(48))), t)
            self.add(IP(src=SERVER_IP, dst=admin) / TCP(sport=22, dport=sport, flags="PA") / Raw(bytes(r.getrandbits(8) for _ in range(r.randint(48, 900)))), t + 0.003)
        self.add(IP(src=admin, dst=SERVER_IP) / TCP(sport=sport, dport=22, flags="FA"), duration - 1)
        self.add(IP(src=SERVER_IP, dst=admin) / TCP(sport=22, dport=sport, flags="FA"), duration - 0.999)
        # normal ARP: who-has / is-at, bindings never change
        for ip in clients + [SERVER_IP]:
            t = r.uniform(0, 20)
            while t < duration:
                self.add(Ether(src=mac_for(ip), dst="ff:ff:ff:ff:ff:ff") /
                         ARP(op=1, hwsrc=mac_for(ip), psrc=ip, pdst=GATEWAY_IP), t)
                self.add(Ether(src=GATEWAY_MAC, dst=mac_for(ip)) /
                         ARP(op=2, hwsrc=GATEWAY_MAC, psrc=GATEWAY_IP, hwdst=mac_for(ip), pdst=ip), t + 0.0003)
                t += r.uniform(40, 90)

    # ---------------------------------------------------------------- attacks
    def syn_scan(self, attacker: str, target: str, ports: list[int], start: float, rate: float, label: bool = True) -> float:
        """nmap -sS style half-open scan; closed ports answer RST/ACK, open ports SYN/ACK then attacker RST."""
        t = start
        for p in ports:
            sp = self.rng.randint(40000, 65000)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=p, flags="S", window=1024), t)
            if p in OPEN_PORTS:
                self.add(IP(src=target, dst=attacker) / TCP(sport=p, dport=sp, flags="SA"), t + 0.0008)
                self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=p, flags="R"), t + 0.0012)
            else:
                self.add(IP(src=target, dst=attacker) / TCP(sport=p, dport=sp, flags="RA"), t + 0.0006)
            t += self.rng.expovariate(rate)
        if label:
            self.label("portscan", [attacker], start, t, f"SYN scan of {len(ports)} ports on {target} at ~{rate:.0f} probes/s")
        return t

    def syn_flood(self, bots: list[str], target: str, dport: int, start: float, duration: float, pps: float) -> None:
        """SYN flood from a small botnet; the victim answers a shrinking share of SYNs (backlog exhaustion)."""
        t = start
        while t < start + duration:
            b = self.rng.choice(bots)
            sp = self.rng.randint(1024, 65535)
            self.add(IP(src=b, dst=target) / TCP(sport=sp, dport=dport, flags="S", seq=self.rng.randint(1, 2**31)), t)
            if self.rng.random() < 0.25:  # backlog full: most SYNs never get a SYN/ACK
                self.add(IP(src=target, dst=b) / TCP(sport=dport, dport=sp, flags="SA"), t + 0.001)
            t += self.rng.expovariate(pps)
        self.label("dos", bots, start, start + duration, f"SYN flood on {target}:{dport} at ~{pps:.0f} pps from {len(bots)} bots")

    def degraded_benign(self, clients: list[str], start: float, duration: float) -> None:
        """Legitimate clients hitting the web server during the flood: slow or unanswered handshakes."""
        t = start
        while t < start + duration:
            c = self.rng.choice(clients)
            if self.rng.random() < 0.4:  # SYN dropped by the overwhelmed server, client retransmits then gives up
                sp = self.rng.randint(32768, 60999)
                for k, d in enumerate([0, 1, 3]):
                    self.add(IP(src=c, dst=SERVER_IP) / TCP(sport=sp, dport=80, flags="S"), t + d)
            else:
                self.tcp_session(t, c, SERVER_IP, 80, b"GET / HTTP/1.1\r\n\r\n", 4000,
                                 handshake_delay=self.rng.uniform(0.2, 0.9))
            t += self.rng.expovariate(1.5)

    def ssh_bruteforce(self, attacker: str, target: str, start: float, attempts: int, rate: float) -> None:
        """Hydra-style SSH guessing: many short connections, banner + a few encrypted packets + server close."""
        t = start
        for _ in range(attempts):
            sp = self.rng.randint(32768, 60999)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=22, flags="S"), t)
            self.add(IP(src=target, dst=attacker) / TCP(sport=22, dport=sp, flags="SA"), t + 0.01)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=22, flags="A"), t + 0.02)
            self.add(IP(src=target, dst=attacker) / TCP(sport=22, dport=sp, flags="PA") / Raw(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"), t + 0.03)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=22, flags="PA") / Raw(b"SSH-2.0-libssh_0.9.6\r\n"), t + 0.04)
            for k in range(3):
                self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=22, flags="PA") / Raw(bytes(self.rng.getrandbits(8) for _ in range(96))), t + 0.06 + 0.04 * k)
                self.add(IP(src=target, dst=attacker) / TCP(sport=22, dport=sp, flags="PA") / Raw(bytes(self.rng.getrandbits(8) for _ in range(64))), t + 0.08 + 0.04 * k)
            self.add(IP(src=target, dst=attacker) / TCP(sport=22, dport=sp, flags="FA"), t + 0.3)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=22, flags="RA"), t + 0.31)
            t += self.rng.expovariate(rate)
        self.label("bruteforce", [attacker], start, t, f"SSH brute force, {attempts} attempts on {target}:22")

    def ftp_bruteforce(self, attacker: str, target: str, start: float, attempts: int, rate: float) -> None:
        """Plain-text FTP guessing: USER/PASS answered by '530 Login incorrect'."""
        t = start
        words = ["123456", "password", "admin", "qwerty", "letmein", "welcome", "root", "toor", "lpu@123"]
        for i in range(attempts):
            sp = self.rng.randint(32768, 60999)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=21, flags="S"), t)
            self.add(IP(src=target, dst=attacker) / TCP(sport=21, dport=sp, flags="SA"), t + 0.005)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=21, flags="A"), t + 0.01)
            self.add(IP(src=target, dst=attacker) / TCP(sport=21, dport=sp, flags="PA") / Raw(b"220 (vsFTPd 3.0.5)\r\n"), t + 0.015)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=21, flags="PA") / Raw(b"USER admin\r\n"), t + 0.02)
            self.add(IP(src=target, dst=attacker) / TCP(sport=21, dport=sp, flags="PA") / Raw(b"331 Please specify the password.\r\n"), t + 0.025)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=21, flags="PA") / Raw(f"PASS {self.rng.choice(words)}{i}\r\n".encode()), t + 0.03)
            self.add(IP(src=target, dst=attacker) / TCP(sport=21, dport=sp, flags="PA") / Raw(b"530 Login incorrect.\r\n"), t + 0.9)
            self.add(IP(src=attacker, dst=target) / TCP(sport=sp, dport=21, flags="FA"), t + 0.91)
            self.add(IP(src=target, dst=attacker) / TCP(sport=21, dport=sp, flags="FA"), t + 0.912)
            t += self.rng.expovariate(rate)
        self.label("bruteforce", [attacker], start, t, f"FTP brute force, {attempts} attempts on {target}:21")

    def arp_spoof(self, attacker: str, victims: list[str], start: float, duration: float, period: float = 2.0) -> None:
        """Bidirectional ARP poisoning (arpspoof/ettercap): unsolicited replies binding the gateway IP (and each
        victim IP) to the attacker's MAC; victims then send gateway-bound frames to the attacker's MAC (MITM)."""
        amac = mac_for(attacker)
        t = start
        while t < start + duration:
            for v in victims:
                self.add(Ether(src=amac, dst=mac_for(v)) / ARP(op=2, hwsrc=amac, psrc=GATEWAY_IP, hwdst=mac_for(v), pdst=v), t)
                self.add(Ether(src=amac, dst=GATEWAY_MAC) / ARP(op=2, hwsrc=amac, psrc=v, hwdst=GATEWAY_MAC, pdst=GATEWAY_IP), t + 0.001)
                # intercepted victim traffic: IP dst is the internet, Ethernet dst is the attacker
                self.add(IP(src=v, dst="93.184.216.20") / TCP(sport=self.rng.randint(32768, 60999), dport=80, flags="PA") / Raw(b"GET /login HTTP/1.1\r\n\r\n"),
                         t + 0.4, src_mac=mac_for(v), dst_mac=amac)
            t += period
        # the attacker also does ordinary IP traffic so its MAC is tied to its IP
        for k in range(6):
            self.add(IP(src=attacker, dst=DNS_IP) / UDP(sport=5353 + k, dport=53) / DNS(id=k, rd=1, qd=DNSQR(qname="example.com")), start + 3 * k)
        self.label("arpspoof", [attacker], start, start + duration, f"ARP poisoning of {len(victims)} victims (gateway {GATEWAY_IP} -> {amac})")

    def backup_burst(self, host: str, start: float, duration: float, conns_per_s: float) -> None:
        """Benign nightly backup: hundreds of short, fully completed rsync connections to one server port."""
        t = start
        while t < start + duration:
            self.tcp_session(t, host, BACKUP_IP, 873, b"@RSYNCD: 31.0\n", self.rng.randint(2000, 9000), rtt=0.0015)
            t += self.rng.expovariate(conns_per_s)

    def write(self, pcap: Path, truth_path: Path, meta: dict) -> None:
        """Sort by time and write pcap + ground truth."""
        self.packets.sort(key=lambda p: p[0])
        write_pcap(pcap, self.packets)
        truth_path.write_text(json.dumps({**meta, "base_ts": BASE_TS, "n_packets": len(self.packets),
                                          "attacks": self.truth}, indent=2))


def clients_for(rng: random.Random, n: int) -> list[str]:
    """Pick n workstation addresses."""
    return [f"192.168.10.{i}" for i in sorted(rng.sample(range(10, 30), n))]


def build_scenario(name: str, seed: int, variant: str = "test") -> Builder:
    """Build one named scenario. ``variant='train'`` randomises attacker IPs/rates so the training set is
    not a copy of the test set."""
    rng = random.Random(f"{name}-{seed}-{variant}")
    b = Builder(rng)
    jitter = (lambda lo, hi: rng.uniform(lo, hi)) if variant == "train" else (lambda lo, hi: (lo + hi) / 2)
    pick = (lambda lst: rng.choice(lst))
    if name == "s1_benign":
        b.benign(120, clients_for(rng, 15))
    elif name == "s2_portscan":
        b.benign(120, clients_for(rng, 12))
        atk = pick(["192.168.10.66", "192.168.10.67", "203.0.113.45"]) if variant == "train" else "192.168.10.66"
        ports = list(range(1, int(jitter(600, 1400))))
        rng.shuffle(ports)
        end = b.syn_scan(atk, SERVER_IP, ports, 30, rate=jitter(60, 400))
        # follow-up: a slower, quieter scan of a workstation (~15 ports per 10 s window in the test capture,
        # i.e. below the SCAN-001 threshold of 20) - this is where the ML layer has to carry the detection
        n2 = 60 if variant == "test" else int(jitter(60, 150))
        b.syn_scan(atk, "192.168.10.12", rng.sample(range(1, 1025), n2), end + 5,
                   rate=1.5 if variant == "test" else jitter(1.0, 20.0))
    elif name == "s3_dos":
        clients = clients_for(rng, 12)
        b.benign(120, clients)
        bots = [f"203.0.113.{rng.randint(100, 200)}" for _ in range(int(jitter(4, 8)))]
        b.syn_flood(bots, SERVER_IP, 80, 40, 30, pps=jitter(600, 2000))
        b.degraded_benign(clients, 40, 30)
    elif name == "s4_bruteforce_arp":
        clients = clients_for(rng, 12)
        b.benign(150, clients)
        b.ssh_bruteforce("203.0.113.45" if variant == "test" else f"203.0.113.{rng.randint(10, 90)}", SERVER_IP, 20, int(jitter(150, 300)), rate=jitter(3, 8))
        b.ftp_bruteforce("192.168.10.77", SERVER_IP, 70, int(jitter(40, 80)), rate=jitter(1.5, 3))
        b.arp_spoof("192.168.10.99", clients[1:4], 100, 40, period=jitter(1.5, 3))
    elif name == "s5_ambiguous":
        clients = clients_for(rng, 8)
        b.benign(360, clients, intensity=0.8)
        # (a) low-and-slow scan: one probe every ~12 s, far below any per-window threshold
        ports = rng.sample([21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443], 17)
        t = 20.0
        for p in ports:
            b.syn_scan("192.168.10.88", SERVER_IP, [p], t, rate=1.0, label=False)
            t += rng.uniform(10, 14)
        b.label("portscan", ["192.168.10.88"], 20.0, t, f"low-and-slow SYN scan, {len(ports)} ports, one probe every ~12 s")
        # (b) benign backup job that is bursty enough to resemble a flood
        b.backup_burst("192.168.10.40", 200, 40, conns_per_s=12)
    else:
        raise ValueError(f"unknown scenario {name}")
    return b


SCENARIOS = ["s1_benign", "s2_portscan", "s3_dos", "s4_bruteforce_arp", "s5_ambiguous"]
DESCRIPTIONS = {
    "s1_benign": "Scenario 1 - normal traffic baseline (DNS, HTTP, TLS, ICMP, SSH admin session, ARP)",
    "s2_portscan": "Scenario 2 - reconnaissance: SYN port scan (vertical + follow-up on a second host)",
    "s3_dos": "Scenario 3 - denial of service: SYN flood from a small botnet against the web server",
    "s4_bruteforce_arp": "Scenario 4 - additional attacks: SSH + FTP brute force and ARP spoofing / MITM",
    "s5_ambiguous": "Scenario 5 - ambiguous: low-and-slow scan (malicious) + bursty backup job (benign)",
}


def main(argv: list[str] | None = None) -> None:
    """CLI entry point: generate test scenarios (and optionally training captures)."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="data", help="output root (pcaps/ and ground_truth/ are created)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train", type=int, default=0, help="also generate N randomised training captures per attack scenario")
    ap.add_argument("--only", nargs="*", default=None, help="restrict to these scenario names")
    args = ap.parse_args(argv)
    out = Path(args.out)
    (out / "pcaps").mkdir(parents=True, exist_ok=True)
    (out / "ground_truth").mkdir(parents=True, exist_ok=True)
    selected = [n for n in SCENARIOS if not args.only or n in args.only]
    for name in selected:
        b = build_scenario(name, args.seed, "test")
        b.write(out / "pcaps" / f"{name}.pcap", out / "ground_truth" / f"{name}.json",
                {"scenario": name, "description": DESCRIPTIONS[name], "seed": args.seed, "variant": "test"})
        print(f"[+] {name}: {len(b.packets)} packets", flush=True)
    if args.train:
        (out / "train").mkdir(parents=True, exist_ok=True)
        for name in [n for n in SCENARIOS[:4] if n in selected]:  # Scenario 5 is deliberately never seen in training
            for k in range(args.train):
                b = build_scenario(name, args.seed + 1000 + k, "train")
                stem = f"train_{name}_{k}"
                b.write(out / "train" / f"{stem}.pcap", out / "train" / f"{stem}.json",
                        {"scenario": name, "seed": args.seed + 1000 + k, "variant": "train"})
                print(f"[+] {stem}: {len(b.packets)} packets", flush=True)


if __name__ == "__main__":
    main()
