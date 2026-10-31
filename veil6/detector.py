"""VEIL6 rule-based detection engine.

Works only on flow metadata + pseudonymous session ids. Raw addresses are
resolved to pseudonyms at ingest and never stored in detector state or alerts.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from . import addressing as A
from .model import Alert, Flow, ICMP6_NS, ICMP6_RA, ICMP6_NA
from .privacy import Pseudonymizer, SessionMapper


@dataclass
class Thresholds:
    addr_scan_unbound: int = 20     # distinct unbound LAN targets / 10 s
    port_scan_ports: int = 15       # distinct dst ports to one host / 10 s
    ndp_ns_per_5s: int = 50
    dos_pps: int = 500              # packets per second to one target
    exfil_bytes_60s: int = 5_000_000
    rotation_new_addrs_60s: int = 6
    brute_attempts_30s: int = 10
    learn_secs: float = 120.0
    cooldown: float = 30.0


RULES = {
    "ADDR_SCAN": ("high", "T1046 Network Service Discovery"),
    "PORT_SCAN": ("medium", "T1046 Network Service Discovery"),
    "ROGUE_RA": ("critical", "T1557 Adversary-in-the-Middle"),
    "NDP_FLOOD": ("high", "T1498 Network Denial of Service"),
    "DOS_FLOOD": ("critical", "T1498 Network Denial of Service"),
    "EXFIL": ("critical", "T1041 Exfiltration Over C2 Channel"),
    "ROTATION_ABUSE": ("medium", "T1564 Hide Artifacts / evasion"),
    "BRUTE_FORCE": ("high", "T1110 Brute Force"),
}

BRUTE_PORTS = {22, 23, 2323}


class Window:
    """Sliding time window of (ts, value)."""

    def __init__(self, span: float):
        self.span, self.q = span, deque()

    def add(self, ts, v):
        self.q.append((ts, v))
        self.prune(ts)

    def prune(self, ts):
        while self.q and self.q[0][0] <= ts - self.span:
            self.q.popleft()

    def total(self):
        return sum(v for _, v in self.q)

    def distinct(self):
        return len({v for _, v in self.q})


class Detector:
    def __init__(self, pseudo: Pseudonymizer, mapper: SessionMapper, router_macs: list[str],
                 th: Thresholds | None = None, start_ts: float = 0.0):
        self.p, self.m, self.th = pseudo, mapper, th or Thresholds()
        self._router_macs = router_macs
        self.start_ts = start_ts
        self.alerts: list[Alert] = []
        self._last: dict[tuple, float] = {}
        self.w = defaultdict(dict)        # rule -> key -> Window
        self.profile: dict[str, set] = defaultdict(set)   # session -> pseudonymous external dsts
        self.stats = defaultdict(int)

    # ---- helpers -----------------------------------------------------
    def _win(self, rule: str, key, span: float) -> Window:
        d = self.w[rule]
        if key not in d:
            d[key] = Window(span)
        return d[key]

    def _alert(self, ts, rule, session, target, detail, **ev):
        k = (rule, session, target)
        if ts - self._last.get(k, -1e9) < self.th.cooldown:
            return
        self._last[k] = ts
        sev, mitre = RULES[rule]
        self.alerts.append(Alert(ts, rule, sev, session, target, detail, dict(mitre=mitre, **ev)))

    def _authorized_router(self, ts, session) -> bool:
        return any(self.p.pseudo(ts, m, "session") == session for m in self._router_macs)

    # ---- ingest ------------------------------------------------------
    def ingest(self, f: Flow) -> None:
        ts, th = f.ts, self.th
        self.stats["flows"] += 1
        self.stats["bytes"] += f.bytes

        # 1. learn bindings from NDP (gateway-side NDP snooping)
        if f.proto == "icmp6" and f.src_mac and f.icmp_type in (ICMP6_NS, ICMP6_NA, ICMP6_RA):
            self.m.observe_binding(ts, f.src, f.src_mac)

        src = self.m.resolve(ts, f.src)
        dst = self.m.resolve(ts, f.dst) if not f.dst.startswith("ff02") else "multicast"
        src_lan = A.in_lan(f.src)

        # R3 ROGUE_RA
        if f.proto == "icmp6" and f.icmp_type == ICMP6_RA:
            sess = self.p.pseudo(ts, f.src_mac, "session") if f.src_mac else src
            if not self._authorized_router(ts, sess):
                self._alert(ts, "ROGUE_RA", sess, "all-nodes",
                            "Router Advertisement from unauthorized node", count=1)

        # R4 NDP_FLOOD
        if f.proto == "icmp6" and f.icmp_type == ICMP6_NS:
            w = self._win("NDP_FLOOD", src, 5)
            w.add(ts, f.pkts)
            if w.total() >= th.ndp_ns_per_5s:
                self._alert(ts, "NDP_FLOOD", src, "neighbor-cache",
                            f"{w.total()} Neighbor Solicitations in 5s", ns=w.total())

        # R1 ADDR_SCAN - probes to LAN addresses with no known binding
        if src_lan and A.in_lan(f.dst) and not self.m.is_bound(ts, f.dst) and f.dst != A.ROUTER_ADDR:
            w = self._win("ADDR_SCAN", src, 10)
            w.add(ts, self.p.pseudo(ts, f.dst, "host"))
            if w.distinct() >= th.addr_scan_unbound:
                self._alert(ts, "ADDR_SCAN", src, "lan/64",
                            f"{w.distinct()} unbound /64 targets probed in 10s", targets=w.distinct())

        # R2 PORT_SCAN
        if f.proto in ("tcp", "udp"):
            w = self._win("PORT_SCAN", (src, dst), 10)
            w.add(ts, f.dport)
            if w.distinct() >= th.port_scan_ports:
                self._alert(ts, "PORT_SCAN", src, dst, f"{w.distinct()} distinct ports in 10s",
                            ports=w.distinct())

        # R5 DOS_FLOOD - packet rate towards a protected LAN (IoT) target
        if A.in_lan(f.dst):
            w = self._win("DOS_FLOOD", dst, 1)
            w.add(ts, f.pkts)
        if A.in_lan(f.dst) and w.total() >= th.dos_pps:
            self._alert(ts, "DOS_FLOOD", dst, dst, f"{w.total()} pkt/s towards target",
                        pps=w.total(), top_source=src)

        # R8 BRUTE_FORCE
        if f.proto == "tcp" and f.dport in BRUTE_PORTS:
            w = self._win("BRUTE_FORCE", (src, dst), 30)
            w.add(ts, 1)
            if w.total() >= th.brute_attempts_30s:
                self._alert(ts, "BRUTE_FORCE", src, dst, f"{w.total()} login attempts (22/23) in 30s",
                            attempts=w.total())

        # R6 EXFIL - outbound to destinations outside the learned profile
        if src_lan and not A.in_lan(f.dst) and not f.dst.startswith("ff02"):
            if ts - self.start_ts < th.learn_secs:
                self.profile[src].add(dst)
            elif dst not in self.profile[src]:
                w = self._win("EXFIL", src, 60)
                w.add(ts, f.bytes)
                if w.total() >= th.exfil_bytes_60s:
                    self._alert(ts, "EXFIL", src, dst,
                                f"{w.total() / 1e6:.1f} MB to never-seen external host in 60s",
                                bytes=w.total())

        # R7 ROTATION_ABUSE
        if f.proto == "icmp6" and f.src_mac and f.icmp_type == ICMP6_NS:
            sess = self.p.pseudo(ts, f.src_mac, "session")
            events = [t for t in self.m.new_addr_events.get(sess, []) if t > ts - 60]
            self.m.new_addr_events[sess] = events
            if len(events) >= th.rotation_new_addrs_60s:
                self._alert(ts, "ROTATION_ABUSE", sess, "self",
                            f"{len(events)} new IPv6 addresses in 60s (normal ~1 per 3 min)",
                            new_addrs=len(events))
