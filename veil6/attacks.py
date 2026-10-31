"""Controlled attack injection for testing VEIL6 detection.

Every attack produces labelled flows (truth_attack) and an Incident record
used by the evaluator. Attacks run only inside the simulated lab.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from . import addressing as A
from .devices import Device
from .model import Flow, Incident, ICMP6_NS, ICMP6_RA

ATTACK_TYPES = [
    "ADDR_SCAN", "PORT_SCAN", "ROGUE_RA", "NDP_FLOOD",
    "DOS_FLOOD", "EXFIL", "ROTATION_ABUSE", "BRUTE_FORCE",
]

DESCRIPTIONS = {
    "ADDR_SCAN": "IPv6 /64 address sweep (ICMPv6 echo) from a rogue LAN node",
    "PORT_SCAN": "TCP SYN port scan against an IoT device",
    "ROGUE_RA": "Rogue Router Advertisement (SLAAC/MITM hijack attempt)",
    "NDP_FLOOD": "Neighbor Solicitation flood (neighbor-cache exhaustion)",
    "DOS_FLOOD": "UDP flood against a camera from an external host",
    "EXFIL": "Compromised device uploading data to an unknown external host",
    "ROTATION_ABUSE": "Compromised device rotating IPv6 addresses rapidly to evade blocking",
    "BRUTE_FORCE": "Telnet/SSH credential brute force against a smart lock",
}


@dataclass
class ScheduledAttack:
    attack: str
    start: float
    duration: float
    attacker: Device | None
    victim: Device | None
    ext: str = ""

    def active(self, ts: float) -> bool:
        return self.start <= ts < self.start + self.duration


class AttackInjector:
    def __init__(self, rng: random.Random, rogue: Device, devices: list[Device]):
        self.rng = rng
        self.rogue = rogue
        self.devices = devices
        self.plan: list[ScheduledAttack] = []

    def _pick(self, kind: str) -> Device:
        return self.rng.choice([d for d in self.devices if d.kind == kind])

    def schedule(self, attack: str, start: float, duration: float | None = None) -> Incident:
        r = self.rng
        dur = duration or {"ADDR_SCAN": 15, "PORT_SCAN": 12, "ROGUE_RA": 10, "NDP_FLOOD": 8,
                           "DOS_FLOOD": 20, "EXFIL": 25, "ROTATION_ABUSE": 40, "BRUTE_FORCE": 25}[attack]
        attacker, victim, ext = self.rogue, None, ""
        if attack == "PORT_SCAN":
            victim = r.choice([d for d in self.devices if d.kind in ("camera", "smart_lock", "hub")])
        elif attack == "DOS_FLOOD":
            attacker, victim, ext = None, self._pick("camera"), A.external_addr(r.randrange(500))
        elif attack == "EXFIL":
            attacker = r.choice([d for d in self.devices if d.kind in ("thermostat", "smart_plug", "sensor")])
            ext = A.external_addr(r.randrange(500, 1000))
        elif attack == "ROTATION_ABUSE":
            attacker = r.choice([d for d in self.devices if d.kind in ("smart_plug", "sensor")])
        elif attack == "BRUTE_FORCE":
            attacker, victim, ext = None, self._pick("smart_lock"), A.external_addr(r.randrange(1000, 1500))
        self.plan.append(ScheduledAttack(attack, start, dur, attacker, victim, ext))
        return Incident(attack, start, start + dur,
                        attacker.name if attacker else f"external:{ext}",
                        victim.name if victim else "lan")

    def tick(self, ts: float) -> list[Flow]:
        out: list[Flow] = []
        for a in self.plan:
            # rotation abuse: switch forced rotation on/off
            if a.attack == "ROTATION_ABUSE" and a.attacker:
                if a.active(ts) and a.attacker.forced_rotate_every is None:
                    a.attacker.forced_rotate_every = 4.0
                    a.attacker.next_rotation = ts
                elif not a.active(ts) and ts >= a.start + a.duration and a.attacker.forced_rotate_every:
                    a.attacker.forced_rotate_every = None
                    a.attacker.next_rotation = ts + a.attacker.rotate_every
            if a.active(ts):
                out.extend(self._emit(a, ts))
        return out

    def _emit(self, a: ScheduledAttack, ts: float) -> list[Flow]:
        r, out = self.rng, []
        lab = dict(truth_attack=a.attack)
        src_dev = a.attacker
        if a.attack == "ADDR_SCAN":
            for _ in range(40):
                out.append(Flow(ts, src_dev.addr, A.temporary_addr(r), "icmp6", icmp_type=128,
                                bytes=64, truth_device=src_dev.name, **lab))
        elif a.attack == "PORT_SCAN":
            for _ in range(30):
                out.append(Flow(ts, src_dev.addr, a.victim.addr, "tcp", sport=r.randint(40000, 60000),
                                dport=r.randint(1, 10000), bytes=60, truth_device=src_dev.name, **lab))
        elif a.attack == "ROGUE_RA":
            out.append(Flow(ts, src_dev.addr, "ff02::1", "icmp6", icmp_type=ICMP6_RA, bytes=120,
                            src_mac=src_dev.mac, truth_device=src_dev.name, **lab))
        elif a.attack == "NDP_FLOOD":
            out.append(Flow(ts, src_dev.addr, "ff02::1:ff00:0", "icmp6", icmp_type=ICMP6_NS, pkts=200,
                            bytes=200 * 86, src_mac=src_dev.mac, truth_device=src_dev.name, **lab))
        elif a.attack == "DOS_FLOOD":
            out.append(Flow(ts, a.ext, a.victim.addr, "udp", sport=r.randint(1024, 65535), dport=554,
                            pkts=2500, bytes=2500 * 512, truth_device="external", **lab))
        elif a.attack == "EXFIL":
            out.append(Flow(ts, src_dev.addr, a.ext, "tcp", sport=r.randint(40000, 60000), dport=8443,
                            pkts=800, bytes=1_000_000, truth_device=src_dev.name, **lab))
        elif a.attack == "ROTATION_ABUSE":
            # traffic itself is benign-looking; the rotation rate is the signal (flows come from Device.rotate)
            pass
        elif a.attack == "BRUTE_FORCE":
            for _ in range(3):
                out.append(Flow(ts, a.ext, a.victim.addr, "tcp", sport=r.randint(1024, 65535),
                                dport=r.choice([22, 23]), pkts=8, bytes=900, truth_device="external", **lab))
        return out
