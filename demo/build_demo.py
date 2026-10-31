"""Build the VEIL6 website into docs/:
    docs/index.html  - project website (landing page)
    docs/demo.html   - live demo dashboard (VEIL6 engine embedded for Pyodide)

    python demo/build_demo.py [--repo https://github.com/<user>/VEIL6]
"""
import argparse
import html
import json
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from veil6.attacks import ATTACK_TYPES, DESCRIPTIONS  # noqa: E402
from veil6.detector import RULES  # noqa: E402
from veil6.simulator import run  # noqa: E402

SIGNAL = {
    "ADDR_SCAN": "≥20 unbound /64 targets in 10 s",
    "PORT_SCAN": "≥15 distinct ports to one host in 10 s",
    "ROGUE_RA": "RA from a non-authorized router session",
    "NDP_FLOOD": "≥50 Neighbor Solicitations in 5 s",
    "DOS_FLOOD": "≥500 pkt/s towards a LAN IoT target",
    "EXFIL": "≥5 MB / 60 s to a never-seen external host",
    "ROTATION_ABUSE": "≥6 new addresses for one session in 60 s",
    "BRUTE_FORCE": "≥10 attempts on 22/23 in 30 s",
}


def arch_svg() -> str:
    boxes = ["IoT Lab", "Capture", "Session Mapper", "Rule Engine", "Alerts", "Evaluator"]
    subs = ["12 devices + rogue", "metadata only", "HMAC pseudonyms", "8 rules", "MITRE-tagged", "P / R / leaks"]
    out, w, gap = [], 158, 30
    for i, (b, s) in enumerate(zip(boxes, subs)):
        x = 10 + i * (w + gap)
        hi = b == "Session Mapper"
        out.append(f'<rect x="{x}" y="30" width="{w}" height="92" rx="12" fill="{"#e7f6f3" if hi else "#f8fafc"}" '
                   f'stroke="{"#0f9d8a" if hi else "#e2e8f0"}" stroke-width="{2 if hi else 1.2}"/>')
        out.append(f'<text x="{x + 16}" y="56" fill="#1d4ed8" font-size="11" font-family="JetBrains Mono">0{i + 1}</text>')
        out.append(f'<text x="{x + 16}" y="82" fill="#0f172a" font-size="15.5" font-weight="700" '
                   f'font-family="Inter">{b}</text>')
        out.append(f'<text x="{x + 16}" y="104" fill="#64748b" font-size="12.5" font-family="Inter">{s}</text>')
        if i < len(boxes) - 1:
            out.append(f'<line x1="{x + w + 4}" y1="76" x2="{x + w + gap - 4}" y2="76" stroke="#94a3b8" '
                       f'stroke-width="1.6" marker-end="url(#ar)"/>')
    out.append('<rect x="10" y="140" width="346" height="26" rx="6" fill="#fef2f2"/>'
               '<text x="22" y="157" fill="#b91c1c" font-size="12" font-family="Inter" font-weight="600">'
               'Raw IPv6 / MAC visible (gateway only)</text>')
    out.append('<rect x="386" y="140" width="704" height="26" rx="6" fill="#e7f6f3"/>'
               '<text x="398" y="157" fill="#0b6e61" font-size="12" font-family="Inter" font-weight="600">'
               'Pseudonyms only from stage 03 onward, raw identifiers never stored</text>')
    return "\n".join(out)


def rules_html() -> str:
    cards = []
    for a in ATTACK_TYPES:
        sev, mitre = RULES[a]
        cards.append(f'<div class="card rule"><div class="top"><span class="name">{a}</span>'
                     f'<span class="sev {sev}">{sev}</span></div><p>{html.escape(DESCRIPTIONS[a])}</p>'
                     f'<div class="sig">{html.escape(SIGNAL[a])}<br><span class="mitre">{mitre}</span></div></div>')
    return "\n".join(cards)


def bench(seeds=20, rounds=2):
    rows = [run(duration=180 + 75 * 8 * rounds + 60, seed=s, rounds=rounds) for s in range(seeds)]
    benign = sum(run(duration=3600, seed=100 + s, attacks=[])["metrics"]["alerts"] for s in range(6))
    m = lambda k, src="metrics": statistics.mean(r[src][k] for r in rows)  # noqa: E731
    return dict(n=seeds * rounds * 8, seeds=seeds, rounds=rounds, recall=m("recall"),
                precision=m("precision"), latency=m("mean_latency_s"), attribution=m("attribution_accuracy"),
                mapping=m("session_mapping_accuracy", "privacy"),
                leaks=sum(r["privacy"]["raw_identifier_leaks_in_alerts"] for r in rows),
                outsider=m("avg_addresses_per_device_seen_by_outsider", "privacy"), benign_alerts=benign)


def stats_html(b) -> str:
    tiles = [(f"{b['recall'] * 100:.0f}%", "Attacks detected (recall)"),
             (f"{b['precision'] * 100:.0f}%", "Alerts that were real attacks (precision)"),
             (f"{b['latency']:.1f}s", "Mean detection latency"),
             (f"{b['attribution'] * 100:.0f}%", "Attributed to the correct device session"),
             (f"{b['mapping'] * 100:.0f}%", "Session mapping accuracy across rotations"),
             (str(b["leaks"]), "Raw IPv6 / MAC strings found in alerts"),
             (str(b["benign_alerts"]), "False alerts in 6 h of benign-only traffic"),
             (f"{b['outsider']:.0f} → 1", "Addresses an outsider sees → VEIL6 sessions per device")]
    return "\n".join(f'<div class="stat"><div class="v">{v}</div><div class="l">{l}</div></div>'
                     for v, l in tiles)


CHECK = ('<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#0f9d8a" stroke-width="2.4" '
         'stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10" fill="#e7f6f3" '
         'stroke="none"/><path d="M7.5 12.5l3 3 6-6.5"/></svg>')
CHECKS = [("No payload inspection", "The engine only ever sees flow metadata."),
          ("No raw IP or MAC at rest", "Address and session tables are keyed by HMAC. Alerts carry pseudonyms only."),
          ("Short retention", "Bindings expire with the IPv6 address valid-lifetime."),
          ("Unlinkable across epochs", "The key K<sub>epoch</sub> rotates, so leaked logs from different days can't be joined."),
          ("Automated leak audit", "Every run regex-scans all alerts for IPv6 and MAC strings, and a unit test fails on any hit.")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="https://github.com/Selvashaju/VEIL6")
    a = ap.parse_args()
    out = ROOT / "docs"
    out.mkdir(exist_ok=True)

    sources = {p.name: p.read_text() for p in sorted((ROOT / "veil6").glob("*.py"))}
    fallback = run(duration=180 + 75 * 8 + 60, seed=7)
    demo = (ROOT / "demo" / "template.html").read_text()
    demo = demo.replace("__SOURCES__", json.dumps(sources)).replace("__FALLBACK__", json.dumps(fallback))
    (out / "demo.html").write_text(demo)

    b = bench()
    desc = (f"{b['n']} controlled attacks across {b['seeds']} random seeds × {b['rounds']} rounds, "
            f"12 virtual IoT devices rotating their IPv6 addresses every ~3 minutes.")
    site = (ROOT / "demo" / "site_template.html").read_text()
    site = (site.replace("__ARCH__", arch_svg()).replace("__RULES__", rules_html())
            .replace("__STATS__", stats_html(b)).replace("__BENCH_DESC__", desc).replace("__REPO__", a.repo)
            .replace("__CHECKS__", "".join(f"<li>{CHECK}<div><b>{t}</b><span>{d}</span></div></li>" for t, d in CHECKS))
            .replace("__N__", str(b["n"])).replace("__LAT__", f"{b['latency']:.1f}"))
    (out / "index.html").write_text(site)
    (out / ".nojekyll").write_text("")
    print("wrote docs/index.html (website) and docs/demo.html (live demo)")
    print(json.dumps(b))


if __name__ == "__main__":
    main()
