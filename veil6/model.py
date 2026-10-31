"""Core data types shared across VEIL6 modules."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

# ICMPv6 message types we care about
ICMP6_RS = 133   # Router Solicitation
ICMP6_RA = 134   # Router Advertisement
ICMP6_NS = 135   # Neighbor Solicitation
ICMP6_NA = 136   # Neighbor Advertisement


@dataclass
class Flow:
    """A flow-level metadata record as seen at the IoT gateway.

    VEIL6 never inspects payloads - only header metadata.
    `truth_*` fields are simulator ground truth used ONLY by the evaluator;
    the detector never reads them.
    """
    ts: float
    src: str            # raw IPv6 source (only visible at capture point)
    dst: str
    proto: str          # "tcp" | "udp" | "icmp6"
    sport: int = 0
    dport: int = 0
    pkts: int = 1
    bytes: int = 64
    icmp_type: Optional[int] = None
    src_mac: Optional[str] = None   # link-layer source (for on-link frames)
    truth_device: Optional[str] = None
    truth_attack: Optional[str] = None


@dataclass
class Alert:
    ts: float
    rule: str
    severity: str
    session: str        # pseudonymous session id - never a raw address
    target: str         # pseudonymous target id
    detail: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    """Ground-truth attack instance injected by the controlled attack module."""
    attack: str
    start: float
    end: float
    attacker: str       # device name of attacker node
    victim: str
