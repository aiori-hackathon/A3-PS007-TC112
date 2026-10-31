"""Privacy layer: pseudonymous session mapping.

Problem: IPv6 privacy extensions (RFC 8981) rotate device addresses, which
breaks per-device security monitoring - but storing MAC/IP to fix that
destroys user privacy.

VEIL6 approach:
  * The gateway sees MAC<->IPv6 bindings in NDP (NS/NA/DAD).
  * Each binding is converted to a keyed pseudonym:
        session_id = HMAC-SHA256(K_epoch, MAC)[:12]
  * The address->session table is keyed by HMAC(K_epoch, addr) and entries
    expire with the address valid-lifetime.
  * Raw MAC / IPv6 addresses are never written to logs or alerts.
  * K_epoch rotates (e.g. daily), so pseudonyms cannot be linked across
    epochs by anyone who later obtains the logs (unlinkability).
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional


class Pseudonymizer:
    def __init__(self, key: Optional[bytes] = None, epoch_len: float = 86400.0):
        self._master = key or os.urandom(32)
        self.epoch_len = epoch_len

    def _epoch_key(self, ts: float) -> bytes:
        epoch = int(ts // self.epoch_len)
        return hmac.new(self._master, f"epoch:{epoch}".encode(), hashlib.sha256).digest()

    def pseudo(self, ts: float, value: str, tag: str) -> str:
        d = hmac.new(self._epoch_key(ts), f"{tag}|{value}".encode(), hashlib.sha256).hexdigest()
        return f"{tag[0].upper()}-{d[:12]}"


class SessionMapper:
    """Maps rotating IPv6 addresses to a stable pseudonymous session per device."""

    def __init__(self, pseudonymizer: Pseudonymizer, addr_ttl: float = 600.0):
        self.p = pseudonymizer
        self.addr_ttl = addr_ttl
        # hashed-address -> (session_id, expiry)
        self._table: dict[str, tuple[str, float]] = {}
        # session_id -> list of first-seen timestamps of new addresses
        self.new_addr_events: dict[str, list[float]] = {}

    def observe_binding(self, ts: float, addr: str, mac: str) -> str:
        """Learn an address binding from NDP traffic. Returns session id."""
        key = self.p.pseudo(ts, addr, "addr")
        sid = self.p.pseudo(ts, mac, "session")
        prev = self._table.get(key)
        if prev is None or prev[1] < ts:
            self.new_addr_events.setdefault(sid, []).append(ts)
        self._table[key] = (sid, ts + self.addr_ttl)
        return sid

    def lookup(self, ts: float, addr: str) -> Optional[str]:
        entry = self._table.get(self.p.pseudo(ts, addr, "addr"))
        if entry and entry[1] >= ts:
            return entry[0]
        return None

    def resolve(self, ts: float, addr: str) -> str:
        """Session id for a LAN address, or an anonymous host pseudonym otherwise."""
        return self.lookup(ts, addr) or self.p.pseudo(ts, addr, "host")

    def is_bound(self, ts: float, addr: str) -> bool:
        return self.lookup(ts, addr) is not None

    def expire(self, ts: float) -> None:
        self._table = {k: v for k, v in self._table.items() if v[1] >= ts}

    def table_size(self) -> int:
        return len(self._table)
