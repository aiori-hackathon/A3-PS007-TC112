"""IPv6 addressing for virtual IoT devices.

Implements privacy-preserving address generation:
  * RFC 7217 style stable-privacy IID (no MAC-derived EUI-64 leak)
  * RFC 8981 style temporary addresses with periodic rotation
"""
from __future__ import annotations

import hashlib
import ipaddress
import random

LAN_PREFIX = ipaddress.IPv6Network("2001:db8:a10e:1::/64")   # documentation prefix
ROUTER_ADDR = str(LAN_PREFIX.network_address + 1)
CLOUD_PREFIX = ipaddress.IPv6Network("2001:db8:c10d::/48")
EXTERNAL_PREFIX = ipaddress.IPv6Network("2001:db8:bad0::/48")


def _iid_to_addr(prefix: ipaddress.IPv6Network, iid: int) -> str:
    return str(prefix.network_address + (iid & ((1 << 64) - 1)))


def stable_privacy_addr(mac: str, secret: bytes, prefix=LAN_PREFIX) -> str:
    """RFC 7217: IID = F(prefix, net_iface, secret) - stable per network, not MAC-derived."""
    h = hashlib.sha256(prefix.network_address.packed + mac.encode() + secret).digest()
    return _iid_to_addr(prefix, int.from_bytes(h[:8], "big"))


def temporary_addr(rng: random.Random, prefix=LAN_PREFIX) -> str:
    """RFC 8981: random IID for a temporary address."""
    iid = rng.getrandbits(64)
    iid &= ~(1 << 57)          # clear the universal/local bit
    return _iid_to_addr(prefix, iid)


def cloud_addr(n: int) -> str:
    return str(CLOUD_PREFIX.network_address + 0x1000 + n)


def external_addr(n: int) -> str:
    return str(EXTERNAL_PREFIX.network_address + 0x2000 + n)


def in_lan(addr: str) -> bool:
    try:
        return ipaddress.IPv6Address(addr) in LAN_PREFIX
    except ValueError:
        return False


def random_mac(rng: random.Random) -> str:
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] & 0xFC) | 0x02     # locally administered unicast
    return ":".join(f"{o:02x}" for o in octets)
