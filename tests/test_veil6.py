import json
import random
import unittest

from veil6 import addressing as A
from veil6.attacks import ATTACK_TYPES
from veil6.privacy import Pseudonymizer, SessionMapper
from veil6.simulator import IPV6_RE, MAC_RE, run


class TestAddressing(unittest.TestCase):
    def test_temporary_addresses_in_prefix_and_random(self):
        rng = random.Random(1)
        addrs = {A.temporary_addr(rng) for _ in range(100)}
        self.assertEqual(len(addrs), 100)
        self.assertTrue(all(A.in_lan(a) for a in addrs))

    def test_stable_privacy_not_mac_derived(self):
        mac = "02:11:22:33:44:55"
        addr = A.stable_privacy_addr(mac, b"secret")
        self.assertNotIn("ff:fe", addr)          # no EUI-64 marker
        self.assertEqual(addr, A.stable_privacy_addr(mac, b"secret"))
        self.assertNotEqual(addr, A.stable_privacy_addr(mac, b"other"))


class TestPrivacy(unittest.TestCase):
    def test_rotating_addresses_map_to_one_session(self):
        p = Pseudonymizer(key=b"k" * 32)
        m = SessionMapper(p)
        rng = random.Random(2)
        mac = "02:aa:bb:cc:dd:ee"
        sids = {m.observe_binding(t, A.temporary_addr(rng), mac) for t in range(0, 600, 60)}
        self.assertEqual(len(sids), 1)

    def test_pseudonyms_unlinkable_across_epochs(self):
        p = Pseudonymizer(key=b"k" * 32, epoch_len=100)
        self.assertNotEqual(p.pseudo(10, "x", "session"), p.pseudo(150, "x", "session"))

    def test_entries_expire(self):
        m = SessionMapper(Pseudonymizer(key=b"k" * 32), addr_ttl=10)
        m.observe_binding(0, "2001:db8:a10e:1::5", "02:00:00:00:00:01")
        self.assertIsNotNone(m.lookup(5, "2001:db8:a10e:1::5"))
        self.assertIsNone(m.lookup(20, "2001:db8:a10e:1::5"))


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run(duration=900, seed=3)

    def test_all_attacks_detected(self):
        for a in ATTACK_TYPES:
            self.assertTrue(all(r["detected"] for r in self.res["per_attack"][a]), a)

    def test_no_raw_identifiers_in_alerts(self):
        alerts = json.dumps([{k: v for k, v in a.items() if k != "_demo_label"} for a in self.res["alerts"]])
        self.assertEqual(IPV6_RE.findall(alerts), [])
        self.assertEqual(MAC_RE.findall(alerts), [])

    def test_benign_only_run_has_no_alerts(self):
        res = run(duration=600, seed=5, attacks=[])
        self.assertEqual(res["metrics"]["alerts"], 0)

    def test_session_mapping_survives_rotation(self):
        self.assertGreater(self.res["privacy"]["avg_addresses_per_device_seen_by_outsider"], 3)
        self.assertEqual(self.res["privacy"]["avg_sessions_per_device_in_veil6"], 1.0)


if __name__ == "__main__":
    unittest.main()
