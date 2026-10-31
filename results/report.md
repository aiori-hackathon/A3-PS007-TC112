# VEIL6 simulation report

Config: `{"duration": 900, "seed": 7, "rounds": 1, "rotate_every": 180.0, "devices": 12, "prefix": "2001:db8:a10e:1::/64"}`

## Detection

| Metric | Value |
|---|---|
| flows | 5391 |
| bytes | 127119262 |
| incidents | 8 |
| alerts | 8 |
| true_positive_alerts | 8 |
| false_positive_alerts | 0 |
| precision | 1.0 |
| recall | 1.0 |
| f1 | 1.0 |
| mean_latency_s | 3.5 |
| attribution_accuracy | 1.0 |

## Privacy

| Metric | Value |
|---|---|
| raw_identifier_leaks_in_alerts | 0 |
| session_mapping_accuracy | 1.0 |
| avg_addresses_per_device_seen_by_outsider | 6.17 |
| avg_sessions_per_device_in_veil6 | 1.0 |
| mapper_table_entries | 66 |

## Per attack

| Attack | Detected | Latency (s) | Attributed |
|---|---|---|---|
| ADDR_SCAN | yes | 0.0 | True |
| PORT_SCAN | yes | 0.0 | True |
| ROGUE_RA | yes | 0.0 | True |
| NDP_FLOOD | yes | 0.0 | True |
| DOS_FLOOD | yes | 0.0 | True |
| EXFIL | yes | 4.0 | True |
| ROTATION_ABUSE | yes | 21.0 | True |
| BRUTE_FORCE | yes | 3.0 | True |

## Alerts

| t (s) | Rule | Severity | Session | Detail |
|---|---|---|---|---|
| 180 | ADDR_SCAN | high | `S-bade69320a32` | 20 unbound /64 targets probed in 10s |
| 255 | PORT_SCAN | medium | `S-bade69320a32` | 15 distinct ports in 10s |
| 330 | ROGUE_RA | critical | `S-bade69320a32` | Router Advertisement from unauthorized node |
| 405 | NDP_FLOOD | high | `S-bade69320a32` | 201 Neighbor Solicitations in 5s |
| 480 | DOS_FLOOD | critical | `S-91a92c095540` | 2500 pkt/s towards target |
| 559 | EXFIL | critical | `S-f263ba22f27f` | 5.0 MB to never-seen external host in 60s |
| 651 | ROTATION_ABUSE | medium | `S-976c34169179` | 6 new IPv6 addresses in 60s (normal ~1 per 3 min) |
| 708 | BRUTE_FORCE | high | `H-fa9d4b97ec93` | 10 login attempts (22/23) in 30s |
