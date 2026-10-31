"""Virtual IoT devices with realistic benign traffic and IPv6 privacy address rotation."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from . import addressing as A
from .model import Flow, ICMP6_NS, ICMP6_NA, ICMP6_RA

# kind -> (cloud endpoint index, port, proto, period_s, bytes)
PROFILES = {
    "camera":     dict(cloud=[1, 2], port=443,  proto="tcp", period=1,  size=(30_000, 50_000)),
    "thermostat": dict(cloud=[3],    port=8883, proto="tcp", period=30, size=(800, 1_400)),
    "smart_lock": dict(cloud=[4],    port=8883, proto="tcp", period=20, size=(300, 700)),
    "sensor":     dict(cloud=[5],    port=5683, proto="udp", period=10, size=(120, 260)),
    "smart_plug": dict(cloud=[6],    port=8883, proto="tcp", period=15, size=(200, 400)),
    "hub":        dict(cloud=[7],    port=443,  proto="tcp", period=5,  size=(1_000, 4_000)),
    "phone":      dict(cloud=[8, 9], port=443,  proto="tcp", period=3,  size=(2_000, 20_000)),
}


@dataclass
class Device:
    name: str
    kind: str
    mac: str
    stable_addr: str
    rng: random.Random
    rotate_every: float = 180.0
    temp_addr: str = ""
    next_rotation: float = 0.0
    addr_history: list = field(default_factory=list)
    # overrides used by controlled attacks (e.g. forced fast rotation)
    forced_rotate_every: float | None = None
    phase: int = 0
    compromised: bool = False   # set by attack module (rogue node starts silent)

    def rotate(self, ts: float, out: list) -> None:
        self.temp_addr = A.temporary_addr(self.rng)
        self.addr_history.append(self.temp_addr)
        period = self.forced_rotate_every or self.rotate_every * self.rng.uniform(0.8, 1.2)
        self.next_rotation = ts + period
        # Duplicate Address Detection / unsolicited NA reveals the MAC<->addr binding at the gateway
        out.append(Flow(ts, self.temp_addr, "ff02::1:ff00:0", "icmp6", icmp_type=ICMP6_NS,
                        bytes=86, src_mac=self.mac, truth_device=self.name))
        out.append(Flow(ts, self.temp_addr, "ff02::1", "icmp6", icmp_type=ICMP6_NA,
                        bytes=86, src_mac=self.mac, truth_device=self.name))

    @property
    def addr(self) -> str:
        return self.temp_addr or self.stable_addr

    def tick(self, ts: float, lan: list["Device"]) -> list[Flow]:
        out: list[Flow] = []
        if ts >= self.next_rotation:
            self.rotate(ts, out)
        p = PROFILES.get(self.kind)
        if p and int(ts) % p["period"] == self.phase % p["period"]:
            dst = A.cloud_addr(self.rng.choice(p["cloud"]))
            size = self.rng.randint(*p["size"])
            out.append(Flow(ts, self.addr, dst, p["proto"], sport=self.rng.randint(40000, 60000),
                            dport=p["port"], pkts=max(1, size // 1200), bytes=size, truth_device=self.name))
        # DNS / NTP housekeeping
        if self.rng.random() < 1 / 60:
            out.append(Flow(ts, self.addr, A.ROUTER_ADDR, "udp", sport=self.rng.randint(40000, 60000),
                            dport=53, pkts=2, bytes=180, truth_device=self.name))
        if self.rng.random() < 1 / 300:
            out.append(Flow(ts, self.addr, A.cloud_addr(99), "udp", sport=123, dport=123,
                            pkts=2, bytes=152, truth_device=self.name))
        # Neighbor Unreachability Detection keeps bindings fresh
        if self.rng.random() < 1 / 30:
            out.append(Flow(ts, self.addr, A.ROUTER_ADDR, "icmp6", icmp_type=ICMP6_NS,
                            bytes=86, src_mac=self.mac, truth_device=self.name))
        # Local LAN traffic: hub polls devices, phone opens the camera app
        if self.kind == "hub" and int(ts) % 10 == 0:
            for d in lan:
                if d.kind in ("sensor", "smart_plug", "smart_lock"):
                    out.append(Flow(ts, self.addr, d.addr, "udp", sport=5683, dport=5683,
                                    pkts=2, bytes=240, truth_device=self.name))
        if self.kind == "phone" and self.rng.random() < 1 / 120:
            cams = [d for d in lan if d.kind == "camera"]
            if cams:
                cam = self.rng.choice(cams)
                for port in (443, 554, 8080):
                    out.append(Flow(ts, self.addr, cam.addr, "tcp", sport=self.rng.randint(40000, 60000),
                                    dport=port, pkts=10, bytes=4_000, truth_device=self.name))
        return out


@dataclass
class Router:
    mac: str
    addr: str = A.ROUTER_ADDR

    def tick(self, ts: float) -> list[Flow]:
        out = []
        if int(ts) % 60 == 0:   # periodic legitimate Router Advertisement
            out.append(Flow(ts, self.addr, "ff02::1", "icmp6", icmp_type=ICMP6_RA, bytes=120,
                            src_mac=self.mac, truth_device="router"))
        if int(ts) % 30 == 0:
            out.append(Flow(ts, self.addr, "ff02::1", "icmp6", icmp_type=ICMP6_NA, bytes=86,
                            src_mac=self.mac, truth_device="router"))
        return out


def build_lab(rng: random.Random, secret: bytes, rotate_every: float = 180.0) -> tuple[Router, list[Device]]:
    """Virtual smart-home / smart-campus IoT lab."""
    layout = [
        ("cam-frontdoor", "camera"), ("cam-lobby", "camera"),
        ("thermo-hall", "thermostat"), ("lock-main", "smart_lock"), ("lock-lab", "smart_lock"),
        ("sensor-temp-1", "sensor"), ("sensor-temp-2", "sensor"), ("sensor-air", "sensor"),
        ("plug-desk", "smart_plug"), ("plug-ac", "smart_plug"),
        ("hub-home", "hub"), ("phone-owner", "phone"),
    ]
    devices = []
    for name, kind in layout:
        mac = A.random_mac(rng)
        d = Device(name=name, kind=kind, mac=mac, stable_addr=A.stable_privacy_addr(mac, secret),
                   rng=random.Random(rng.random()), rotate_every=rotate_every)
        d.next_rotation = rng.uniform(0, 5)
        d.phase = rng.randrange(60)
        devices.append(d)
    return Router(mac=A.random_mac(rng)), devices
