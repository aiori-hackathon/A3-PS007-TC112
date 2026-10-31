"""VEIL6 command line.

    python -m veil6 run                 # full simulation, all 8 attacks
    python -m veil6 run --rounds 3 --seed 42 --out results
    python -m veil6 bench --seeds 10    # multi-seed benchmark
"""
from __future__ import annotations

import argparse
import json
import os
import statistics

from .attacks import ATTACK_TYPES
from .simulator import run


def write_report(res: dict, out: str) -> None:
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "report.json"), "w") as fh:
        json.dump(res, fh, indent=2)
    m, p = res["metrics"], res["privacy"]
    lines = ["# VEIL6 simulation report", "",
             f"Config: `{json.dumps(res['config'])}`", "",
             "## Detection", "", "| Metric | Value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in m.items()]
    lines += ["", "## Privacy", "", "| Metric | Value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in p.items()]
    lines += ["", "## Per attack", "", "| Attack | Detected | Latency (s) | Attributed |", "|---|---|---|---|"]
    for a, runs in res["per_attack"].items():
        for r in runs:
            lines.append(f"| {a} | {'yes' if r['detected'] else 'NO'} | {r['latency']} | {r['attributed']} |")
    lines += ["", "## Alerts", "", "| t (s) | Rule | Severity | Session | Detail |", "|---|---|---|---|---|"]
    for a in res["alerts"]:
        lines.append(f"| {a['ts']} | {a['rule']} | {a['severity']} | `{a['session']}` | {a['detail']} |")
    with open(os.path.join(out, "report.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="veil6", description="Privacy-aware IPv6 IoT security monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run one simulation")
    r.add_argument("--duration", type=int, default=900)
    r.add_argument("--seed", type=int, default=7)
    r.add_argument("--rounds", type=int, default=1)
    r.add_argument("--attacks", default="all", help="comma list or 'all': " + ",".join(ATTACK_TYPES))
    r.add_argument("--rotate-every", type=float, default=180.0)
    r.add_argument("--out", default="results")
    b = sub.add_parser("bench", help="multi-seed benchmark")
    b.add_argument("--seeds", type=int, default=10)
    b.add_argument("--rounds", type=int, default=2)
    a = ap.parse_args(argv)

    if a.cmd == "run":
        attacks = None if a.attacks == "all" else [x.strip().upper() for x in a.attacks.split(",")]
        dur = max(a.duration, 180 + 75 * len(attacks or ATTACK_TYPES) * a.rounds + 60)
        res = run(duration=dur, seed=a.seed, attacks=attacks, rounds=a.rounds, rotate_every=a.rotate_every)
        write_report(res, a.out)
        print(f"\nVEIL6  |  {res['config']['devices']} IoT devices  |  {res['metrics']['flows']} flows  "
              f"|  {res['metrics']['incidents']} attacks injected\n")
        for k, v in res["per_attack"].items():
            for x in v:
                mark = "DETECTED" if x["detected"] else "MISSED  "
                print(f"  {k:<15} {mark}  latency={x['latency']}s  attributed={x['attributed']}")
        print("\n  Detection :", json.dumps(res["metrics"]))
        print("  Privacy   :", json.dumps(res["privacy"]))
        print(f"\n  Reports written to {a.out}/report.md and {a.out}/report.json")
    else:
        rows = []
        for s in range(a.seeds):
            dur = 180 + 75 * len(ATTACK_TYPES) * a.rounds + 60
            res = run(duration=dur, seed=s, rounds=a.rounds)
            rows.append(res["metrics"] | res["privacy"])
        for key in ("precision", "recall", "f1", "mean_latency_s", "attribution_accuracy",
                    "session_mapping_accuracy", "raw_identifier_leaks_in_alerts"):
            vals = [r[key] for r in rows if r[key] is not None]
            print(f"{key:<34} mean={statistics.mean(vals):.3f}  min={min(vals)}  max={max(vals)}")


if __name__ == "__main__":
    main()
