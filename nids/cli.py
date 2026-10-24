"""Command-line interface.

    python -m nids generate  [--train 3]          # write the 5 scenario pcaps (+ training captures)
    python -m nids train                          # fit RandomForest + IsolationForest
    python -m nids analyze --pcap data/pcaps/s2_portscan.pcap [--json out.json] [--csv out.csv] [--verbose]
    python -m nids evaluate                       # metrics, confusion matrices, figures for all scenarios
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def _table(rows: list[list[str]], headers: list[str]) -> str:
    """Plain-text table without third-party dependencies."""
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
    line = "+" + "+".join("-" * (w_ + 2) for w_ in widths) + "+"
    fmt = lambda r: "| " + " | ".join(str(c).ljust(w_) for c, w_ in zip(r, widths)) + " |"  # noqa: E731
    return "\n".join([line, fmt(headers), line] + [fmt(r) for r in rows] + [line])


def cmd_analyze(args: argparse.Namespace) -> int:
    from detection.engine import DEFAULT_MODEL, analyze
    from detection.ml import Models

    model_path = Path(args.model) if args.model else DEFAULT_MODEL
    if not model_path.exists():
        print(f"model not found at {model_path}; run `python -m nids train` first", file=sys.stderr)
        return 2
    res = analyze(args.pcap, Models.load(model_path))
    ev = sorted(res.events, key=lambda e: (SEV_ORDER[e["severity"]], e["window_start"]))
    t = res.timing
    print(f"\nFile: {args.pcap}\nPackets: {t['packets']}  capture span: {t['capture_seconds']} s  host-windows: {t['windows']}")
    print(f"Processing: {t['total_s']} s ({t['packets_per_s']:.0f} packets/s, {t['ms_per_window']} ms per window, "
          f"{t['realtime_factor']}x faster than real time)")
    counts: dict[str, int] = {}
    for e in res.events:
        counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
    print(f"Flagged host-windows: {len(res.events)} {counts if counts else '(none - traffic looks benign)'}\n")
    if ev:
        rows = [[e["event_id"], e["window_start"][11:], e["src"], (e["dsts"] or "-")[:31], (e["dst_ports"] or "-")[:18],
                 e["verdict"], e["severity"], f'{e["confidence"]:.2f}', e["layers"], e["rule_ids"] or "-"]
                for e in ev[: args.limit]]
        print(_table(rows, ["id", "window(UTC)", "src", "dst(s)", "ports", "verdict", "sev", "conf", "layers", "rules"]))
        if len(ev) > args.limit:
            print(f"... {len(ev) - args.limit} more (see --json/--csv)")
        print("\nWhy (top events):")
        for e in ev[: (args.limit if args.verbose else 5)]:
            print(f"- {e['event_id']} {e['src']} {e['verdict']}/{e['severity']}:")
            for part in e["why"].split(" | "):
                print(textwrap.indent(textwrap.fill(part, 110), "    "))
    for v in res.victim_alerts:
        print(f"[victim view] {v['rule_id']} {v['target']} at {v['window_start_iso']}: {v['why']}")
    if res.arp_events:
        a = res.arp_events[0]
        print(f"[arp] {len(res.arp_events)} binding changes, first: {a['ip']} known at {a['known_mac']} "
              f"now claimed by {a['claimed_mac']} (sender {a['sender']})")
    if args.json:
        Path(args.json).write_text(json.dumps({"pcap": args.pcap, "timing": t, "events": res.events,
                                               "victim_alerts": res.victim_alerts, "arp_events": res.arp_events[:50]},
                                              indent=2, default=str))
        print(f"\nJSON written to {args.json}")
    if args.csv:
        res.events_frame().to_csv(args.csv, index=False)
        print(f"CSV written to {args.csv}")
    return 0


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m nids", description="AI-driven network intrusion detection")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse a pcap and print explained alerts")
    a.add_argument("--pcap", required=True)
    a.add_argument("--model", default=None)
    a.add_argument("--json", default=None)
    a.add_argument("--csv", default=None)
    a.add_argument("--limit", type=int, default=15)
    a.add_argument("--verbose", action="store_true")
    sub.add_parser("generate", help="generate scenario pcaps (passes remaining args to traffic.generate)", add_help=False)
    sub.add_parser("train", help="train the ML layer (passes remaining args to detection.train)", add_help=False)
    sub.add_parser("evaluate", help="evaluate on the 5 scenarios (passes remaining args to evaluation.evaluate)", add_help=False)
    args, rest = ap.parse_known_args(argv)
    if args.cmd == "analyze":
        sys.exit(cmd_analyze(args))
    if args.cmd == "generate":
        from traffic.generate import main as m
    elif args.cmd == "train":
        from detection.train import main as m
    else:
        from evaluation.evaluate import main as m
    m(rest)


if __name__ == "__main__":
    main()
