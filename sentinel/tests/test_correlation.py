"""Layer-2 tests on the synthetic capture (tests/make_synthetic_pcap.py).

The fixtures are the real outputs of Suricata 7 (Sentinel rule set), Zeek 9.0.1
(JSON logs) and the Sentinel sensor on that capture. The capture contains six
attack patterns plus normal web/DNS traffic; this test is the acceptance
criterion of roadmap phase 3: every pattern must become an incident, and the
status must turn red.
"""

import struct
import tempfile
import time
import unittest
from pathlib import Path

from cyberdistro_sentinel.config import Thresholds
from cyberdistro_sentinel.events import Event, load_offline
from cyberdistro_sentinel.rules import CONFIRMED, HIGH, Correlator
from cyberdistro_sentinel.sensor import parse_dhcp, parse_frame
from cyberdistro_sentinel.status import GREEN, GREY, RED, YELLOW, Health, decide
from cyberdistro_sentinel.store import Store

FX = Path(__file__).parent / "fixtures"
OK = Health(True, True, True, True)


def replay():
    evs = load_offline(FX / "eve.json.gz", FX / "zeek", FX / "sensor.jsonl")
    c = Correlator()
    c.run(evs)
    return c, {i.rule: i for i in c.incidents.values()}


class TestSyntheticCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c, cls.by_rule = replay()

    def test_all_six_patterns_detected(self):
        for rule in ("port_scan", "brute_force", "arp_spoof", "dns_nxdomain_burst",
                     "dns_tunnel", "beaconing", "suricata_alert"):
            self.assertIn(rule, self.by_rule, rule)

    def test_port_scan_facts(self):
        i = self.by_rule["port_scan"]
        self.assertEqual((i.src, i.dst), ("192.168.1.57", "192.168.1.10"))
        self.assertEqual(i.facts["ports"], 1000)
        self.assertEqual((i.level, i.severity), (CONFIRMED, HIGH))   # target is this PC

    def test_brute_force_counts_only_answered_connections(self):
        i = self.by_rule["brute_force"]
        self.assertEqual(i.facts["attempts"], 60)
        self.assertEqual(i.facts["port"], 22)

    def test_gateway_arp_spoof_is_confirmed_high(self):
        i = self.by_rule["arp_spoof"]
        self.assertTrue(i.facts["is_gateway"])
        self.assertEqual(i.facts["old_mac"], "aa:aa:aa:00:00:01")
        self.assertEqual(i.facts["new_mac"], "dc:a6:32:00:00:57")
        self.assertEqual((i.level, i.severity), (CONFIRMED, HIGH))

    def test_beacon_interval(self):
        i = self.by_rule["beaconing"]
        self.assertEqual(i.facts["interval_s"], 60)
        self.assertEqual(i.dst, "185.220.10.10")

    def test_every_incident_has_evidence(self):
        for i in self.c.incidents.values():
            self.assertTrue(i.evidence, i.key)
            self.assertLessEqual(len(i.evidence), 20)

    def test_baseline_traffic_alone_raises_nothing(self):
        evs = [e for e in load_offline(FX / "eve.json.gz", FX / "zeek", FX / "sensor.jsonl")
               if e.engine == "zeek" and (e.src == "192.168.1.10" and e.dport in (53, 80))
               and "evil" not in (e.data.get("query") or "") and e.data.get("rcode") != "NXDOMAIN"
               and not str(e.data.get("query", "")).endswith(".xyz")]
        c = Correlator()
        c.run(evs)
        self.assertEqual([i.rule for i in c.incidents.values()], [])

    def test_store_and_status_red(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(Path(d) / "s.db")
            for i in self.c.incidents.values():
                st.upsert_incident(i)
            st.commit()
            incs = st.incidents()
            now = max(i["last_ts"] for i in incs)
            self.assertEqual(decide(incs, OK, now)["colour"], RED)
            self.assertEqual(decide(incs, Health(True, False, True, True), now)["colour"], GREY)
            self.assertEqual(decide(incs, OK, now + 7200)["colour"], GREEN)   # outside the window


class TestStatusRules(unittest.TestCase):
    def inc(self, level, sev, ts=1000.0):
        return {"level": level, "severity": sev, "last_ts": ts, "status": "aperto"}

    def test_suspicious_high_is_yellow_not_red(self):
        self.assertEqual(decide([self.inc("sospetto", "alta")], OK, 1000)["colour"], YELLOW)

    def test_low_is_green(self):
        self.assertEqual(decide([self.inc("confermato", "bassa")], OK, 1000)["colour"], GREEN)

    def test_closed_incident_ignored(self):
        i = self.inc("confermato", "alta")
        i["status"] = "chiuso"
        self.assertEqual(decide([i], OK, 1000)["colour"], GREEN)


class TestSensorParsing(unittest.TestCase):
    def test_arp_reply(self):
        eth = bytes.fromhex("ffffffffffff" "dca632000057" "0806")
        arp = bytes.fromhex("0001080006040002" "dca632000057" "c0a80101" "bbbbbb000010" "c0a8010a")
        recs = parse_frame(eth + arp)
        self.assertEqual(recs, [{"kind": "arp", "ip": "192.168.1.1", "mac": "dc:a6:32:00:00:57",
                                 "op": "reply", "eth_src": "dc:a6:32:00:00:57"}])

    def test_dhcp_hostname(self):
        p = bytearray(240)
        p[0] = 1
        p[28:34] = bytes.fromhex("001122334455")
        p[236:240] = b"\x63\x82\x53\x63"
        p += bytes([53, 1, 3, 12, 6]) + b"laptop" + bytes([50, 4, 192, 168, 1, 23, 255])
        d = parse_dhcp(bytes(p))
        self.assertEqual((d["mac"], d["ip"], d["hostname"]), ("00:11:22:33:44:55", "192.168.1.23", "laptop"))

    def test_truncated_frames_do_not_crash(self):
        for n in range(0, 60):
            parse_frame(bytes(n))


class TestNewDevice(unittest.TestCase):
    def test_device_after_learning_period_is_flagged(self):
        c = Correlator(Thresholds(learning_period=60))
        mk = lambda ts, ip, mac: Event(ts=ts, engine="sensor", kind="arp", ref=f"s{ts}", src=ip,
                                        data={"mac": mac})
        c.run([mk(0, "192.168.1.2", "00:00:00:00:00:02"), mk(100, "192.168.1.9", "00:00:00:00:00:09")])
        rules = sorted(i.rule for i in c.incidents.values())
        self.assertEqual(rules, ["new_device"])
        self.assertEqual(next(iter(c.incidents.values())).facts["ip"], "192.168.1.9")


if __name__ == "__main__":
    unittest.main()
