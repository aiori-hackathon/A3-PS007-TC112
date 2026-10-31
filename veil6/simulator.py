"""End-to-end simulation: virtual IPv6 IoT lab -> VEIL6 monitor -> evaluation."""
from __future__ import annotations

import json
import random
import re
from collections import defaultdict
from dataclasses import asdict

from . import addressing as A
from .attacks import ATTACK_TYPES, DESCRIPTIONS, AttackInjector
from .detector import Detector, Thresholds
from .devices import Device, build_lab
from .model import Flow, Incident
from .privacy import Pseudonymizer, SessionMapper

IPV6_RE = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I)
MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)


def run(duration: int = 900, seed: int = 7, attacks: list[str] | None = None, rounds: int = 1,
        rotate_every: float = 180.0, attack_start: float = 180.0, spacing: float = 75.0,
        thresholds: Thresholds | None = None) -> dict:
    rng = random.Random(seed)
    secret = rng.randbytes(16)
    router, devices = build_lab(rng, secret, rotate_every)
    rogue_mac = A.random_mac(rng)
    rogue = Device("rogue-node", "rogue", rogue_mac, A.stable_privacy_addr(rogue_mac, secret),
                   random.Random(rng.random()), rotate_every=rotate_every)
    lan = devices + [rogue]

    pseudo = Pseudonymizer(key=rng.randbytes(32))
    mapper = SessionMapper(pseudo, addr_ttl=600)
    det = Detector(pseudo, mapper, router_macs=[router.mac], th=thresholds)

    inj = AttackInjector(rng, rogue, devices)
    incidents: list[Incident] = []
    t = attack_start
    for _ in range(rounds):
        for a in (ATTACK_TYPES if attacks is None else attacks):
            if t + 45 > duration:
                break
            incidents.append(inj.schedule(a, t))
            t += spacing

    timeline = defaultdict(lambda: dict(flows=0, bytes=0, attack_flows=0))
    mapping_ok = mapping_total = 0
    observed_addrs = defaultdict(set)   # what an outside observer can link: raw addresses per device
    sessions_seen = defaultdict(set)    # what VEIL6 links: sessions per device

    for ts in range(duration):
        flows: list[Flow] = router.tick(ts)
        for d in lan:
            flows += d.tick(ts, devices)
        flows += inj.tick(ts)
        for f in flows:
            det.ingest(f)
            b = timeline[ts // 10 * 10]
            b["flows"] += 1
            b["bytes"] += f.bytes
            b["attack_flows"] += 1 if f.truth_attack else 0
            # session-mapping accuracy on LAN-originated device traffic (after binding warm-up)
            dev = next((x for x in lan if x.name == f.truth_device), None)
            if dev and A.in_lan(f.src) and ts > 10:
                expected = pseudo.pseudo(ts, dev.mac, "session")
                got = mapper.lookup(ts, f.src)
                mapping_total += 1
                mapping_ok += got == expected
                observed_addrs[dev.name].add(f.src)
                if got:
                    sessions_seen[dev.name].add(got)
        if ts % 30 == 0:
            mapper.expire(ts)

    # ---- evaluation --------------------------------------------------
    sess_of = {d.name: pseudo.pseudo(0, d.mac, "session") for d in lan}
    # an alert still counts for an incident while the rule's sliding window holds attack evidence
    grace = {"EXFIL": 60, "ROTATION_ABUSE": 60, "BRUTE_FORCE": 30}
    matched_alerts = set()
    per_attack = {}
    for inc in incidents:
        hits = [i for i, a in enumerate(det.alerts)
                if a.rule == inc.attack and inc.start <= a.ts <= inc.end + grace.get(inc.attack, 15)]
        matched_alerts.update(hits)
        first = det.alerts[hits[0]] if hits else None
        attributed = None
        if first and inc.attacker in sess_of:
            attributed = first.session == sess_of[inc.attacker]
        elif first and inc.victim in sess_of:      # external attacker: victim must be identified
            attributed = sess_of[inc.victim] in (first.session, first.target)
        per_attack.setdefault(inc.attack, []).append(dict(
            start=inc.start, detected=bool(hits),
            latency=round(first.ts - inc.start, 1) if first else None,
            attributed=attributed, attacker=inc.attacker, victim=inc.victim))

    n_alerts = len(det.alerts)
    tp_alerts = len(matched_alerts)
    detected = sum(r["detected"] for v in per_attack.values() for r in v)
    lat = [r["latency"] for v in per_attack.values() for r in v if r["latency"] is not None]
    attr = [r["attributed"] for v in per_attack.values() for r in v if r["attributed"] is not None]
    precision = tp_alerts / n_alerts if n_alerts else 1.0
    recall = detected / len(incidents) if incidents else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    alerts_json = json.dumps([a.to_dict() for a in det.alerts])
    leaks = len(IPV6_RE.findall(alerts_json)) + len(MAC_RE.findall(alerts_json))

    device_names = {d.name: d.kind for d in devices}
    alias = {v: k for k, v in sess_of.items()}

    return dict(
        config=dict(duration=duration, seed=seed, rounds=rounds, rotate_every=rotate_every,
                    devices=len(devices), prefix=str(A.LAN_PREFIX)),
        metrics=dict(
            flows=det.stats["flows"], bytes=det.stats["bytes"], incidents=len(incidents),
            alerts=n_alerts, true_positive_alerts=tp_alerts, false_positive_alerts=n_alerts - tp_alerts,
            precision=round(precision, 3), recall=round(recall, 3), f1=round(f1, 3),
            mean_latency_s=round(sum(lat) / len(lat), 2) if lat else None,
            attribution_accuracy=round(sum(attr) / len(attr), 3) if attr else None,
        ),
        privacy=dict(
            raw_identifier_leaks_in_alerts=leaks,
            session_mapping_accuracy=round(mapping_ok / mapping_total, 4) if mapping_total else None,
            avg_addresses_per_device_seen_by_outsider=round(
                sum(len(v) for k, v in observed_addrs.items() if k in device_names) / len(device_names), 2),
            avg_sessions_per_device_in_veil6=round(
                sum(len(v) for k, v in sessions_seen.items() if k in device_names) / len(device_names), 2),
            mapper_table_entries=mapper.table_size(),
        ),
        per_attack=per_attack,
        descriptions=DESCRIPTIONS,
        alerts=[dict(a.to_dict(), _demo_label=alias.get(a.session, "external/unknown"))
                for a in det.alerts],
        timeline=[dict(t=k, **v) for k, v in sorted(timeline.items())],
        devices=[dict(name=d.name, kind=d.kind, session=sess_of[d.name],
                      addresses_used=len(d.addr_history)) for d in lan],
    )
