# VEIL6 — Privacy-Aware IPv6 IoT Security Monitoring

**AIORI-3 · Problem Statement PS-007** · Team **CIPHER NEST** (A3-PS007-TC112)
Faculty mentor: Beulah Christalin Latha C, Associate Professor, Karunya Institute of Technology and Sciences

## Team Introduction Video

[Watch the VEIL6 Team Introduction Video](https://youtu.be/t7SmZdnyiBs)

## 📄 Submission documents

- [Project submission PDF](CIPHER_NEST_A3-PS007-TC112_VEIL6_Submission.pdf)

## 🔴 Project website & live working demo

- **Website:** https://claude.ai/artifact/FQPvgiZcpa4affFQg8dNgh (`docs/index.html`)
- **Live demo:** https://claude.ai/artifact/FQPvgiZcpa4affFQg8dNgh (open "Launch live demo") (`docs/demo.html`)

The demo runs the real VEIL6 Python engine **inside your browser** (Pyodide). You pick a seed, which attacks to inject and the address-rotation period, then watch the gateway traffic, the alerts and the per-device sessions as the run plays back. If the Python runtime cannot load (offline), the page replays a recorded run of the same code.

---

## The problem

IPv6 privacy extensions (RFC 8981) give IoT devices short-lived random addresses. That protects users from tracking, but it also breaks per-device security monitoring, because the "same" device looks like a new host every few minutes. The usual fix is to log MAC addresses and IPs, which defeats the privacy the extensions were built to give.

**VEIL6 aims to get both:** per-device attack detection and attribution that survive address rotation, without storing any raw IPv6 address or MAC address.

## How it works

```
 Virtual IPv6 IoT lab ──► Gateway capture ──► Session mapper ──► Rule engine ──► Alerts ──► Evaluator
 12 devices + rogue      flow metadata only   NDP binding →      8 sliding-     pseudonymous  precision/recall
 RFC 8981 rotation       (no payload)         HMAC pseudonym     window rules   MITRE-tagged  latency, leaks
```

| Module | Purpose |
|---|---|
| `veil6/addressing.py` | RFC 7217 stable-privacy IIDs (not derived from the MAC) and RFC 8981 temporary addresses with rotation |
| `veil6/devices.py` | Virtual IoT lab: cameras, thermostat, smart locks, sensors, plugs, hub, phone, all sending realistic benign traffic (telemetry, DNS, NTP, NUD, LAN polling, app access) |
| `veil6/privacy.py` | `Pseudonymizer` (HMAC-SHA256 with a per-epoch key) and `SessionMapper` (rotating address → stable pseudonymous session, with TTL expiry) |
| `veil6/detector.py` | Rule engine. It only ever stores pseudonyms. |
| `veil6/attacks.py` | Controlled attack injection with ground-truth labels |
| `veil6/simulator.py` | Runs the lab end to end and evaluates detection and privacy |
| `demo/` | Builds the website (`docs/index.html`) and the live demo (`docs/demo.html`) |

### Privacy design

1. **Metadata only.** VEIL6 reads flow headers (addresses, ports, protocol, sizes, ICMPv6 type). It never reads payloads.
2. **Pseudonymize at ingest.** The gateway learns MAC↔IPv6 bindings from NDP (NS/NA/DAD). Each binding becomes `session = HMAC(K_epoch, MAC)`, and the address table is keyed by `HMAC(K_epoch, addr)`.
3. **Minimal retention.** Address-table entries expire with the address lifetime (TTL).
4. **Unlinkable across epochs.** `K_epoch` rotates, for example daily, so leaked logs from different epochs can't be joined.
5. **Audited.** Every run regex-scans all alerts for IPv6 and MAC strings. The leak count must be 0, and a unit test enforces this.

### Detection rules

| Rule | Signal | Severity | MITRE ATT&CK |
|---|---|---|---|
| ADDR_SCAN | ≥20 distinct *unbound* /64 targets probed in 10 s | high | T1046 |
| PORT_SCAN | ≥15 distinct ports to one host in 10 s | medium | T1046 |
| ROGUE_RA | Router Advertisement from a non-authorized router session | critical | T1557 |
| NDP_FLOOD | ≥50 Neighbor Solicitations from one session in 5 s | high | T1498 |
| DOS_FLOOD | ≥500 pkt/s towards a LAN IoT target | critical | T1498 |
| EXFIL | ≥5 MB in 60 s to an external host outside the device's learned profile | critical | T1041 |
| ROTATION_ABUSE | ≥6 new IPv6 addresses for one session in 60 s (normal is about 1 per 3 min) | medium | T1564 |
| BRUTE_FORCE | ≥10 connection attempts to 22/23 in 30 s | high | T1110 |

ROTATION_ABUSE and the device attribution for EXFIL depend on session mapping. An IP-based monitor loses track of a device that keeps changing its address; VEIL6 keeps tracking it.

## Run it

Needs only Python 3.10+. There are no third-party dependencies.

```bash
python -m veil6 run                       # all 8 attacks, writes results/report.md + report.json
python -m veil6 run --attacks EXFIL,ROGUE_RA --rotate-every 60 --seed 3
python -m veil6 bench --seeds 20 --rounds 2   # multi-seed benchmark
python -m unittest discover -s tests -v       # 9 tests
python demo/build_demo.py                     # rebuild website + demo after code changes
```

### Enable the live demo (GitHub Pages)
Go to repo **Settings → Pages → Source: Deploy from a branch → `main` / `/docs`**. The website then goes live at `https://<user>.github.io/<repo>/`, with the demo at `/demo.html`. The `docs/` folder is a plain static site, so you can also drag it onto Netlify Drop or deploy it on Vercel.

## Results (simulated lab)

20 seeds × 2 rounds × 8 attacks = 320 injected attacks (`results/benchmark.txt`):

| Metric | Value |
|---|---|
| Recall (attacks detected) | **1.000** |
| Precision (alerts matching a real attack) | **1.000** |
| Mean detection latency | **3.2 s** |
| Attribution to the correct device/session | **100 %** |
| Session-mapping accuracy across rotations | **100 %** |
| Raw IPv6/MAC strings in alerts | **0** |
| False alerts in 6 h of benign-only traffic | **0** |

On average an outside observer sees about 6 different addresses per device in a 15-minute run. VEIL6 links them to exactly 1 pseudonymous session.

### Limitations (honest scope)
- The traffic is **synthetic** and the thresholds were tuned on this simulated lab, so the perfect scores reflect a controlled scenario. Real networks will produce false positives that need tuning.
- The session mapper assumes the monitor sits at the gateway where NDP is visible. Devices behind another router would need DHCPv6 or RA-guard telemetry.
- Next step: replay real IPv6 IoT captures (pcap → flow records with Scapy) through the same `Detector.ingest()` interface, and add adaptive or ML baselines next to the rules.

## Team roles
- **Shajilin Benadict S**: security rules, controlled attack testing, result evaluation, final demo
- **Jayakumar V**: IPv6 lab, virtual IoT devices, address rotation, session mapping

All addresses use the IPv6 documentation prefix `2001:db8::/32`. Attacks run only inside the simulated lab.
