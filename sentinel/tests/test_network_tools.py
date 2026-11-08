"""2a/2b/2c building blocks: active census frames, mirror detection, Wi-Fi/DNS
checks and the deep-inspection per-device summary. All pure, no network."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from cyberdistro_sentinel import discover, inspect as insp, netcheck as nc

ME, GW, CAM = "192.168.1.35", "192.168.1.1", "192.168.1.20"


class TestDiscover(unittest.TestCase):
    def test_arp_request_frame_is_well_formed(self):
        f = discover.arp_request_frame("aa:bb:cc:dd:ee:35", ME, CAM)
        self.assertEqual(f[:6], b"\xff\xff\xff\xff\xff\xff")          # broadcast
        self.assertEqual(f[6:12], bytes.fromhex("aabbccddee35"))     # our mac
        self.assertEqual(f[12:14], b"\x08\x06")                      # ethertype ARP
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", f[14:22])
        self.assertEqual((htype, ptype, op), (1, 0x0800, 1))         # request
        self.assertEqual(f[22:28], bytes.fromhex("aabbccddee35"))    # sender mac
        self.assertEqual(f[28:32], bytes([192, 168, 1, 35]))         # sender ip
        self.assertEqual(f[38:42], bytes([192, 168, 1, 20]))         # target ip

    def test_subnet_hosts_excludes_self_net_and_broadcast(self):
        hosts = discover.subnet_hosts(ME, "255.255.255.0")
        self.assertEqual(len(hosts), 253)                            # 254 usable minus self
        self.assertNotIn(ME, hosts)
        self.assertIn(GW, hosts)
        self.assertNotIn("192.168.1.0", hosts)
        self.assertNotIn("192.168.1.255", hosts)

    def test_subnet_hosts_refuses_huge_mask(self):
        self.assertEqual(discover.subnet_hosts("10.0.0.5", "255.0.0.0"), [])

    def test_is_tap_detects_foreign_traffic(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "conn.log"
            with open(log, "w") as fh:
                for i in range(30):                                 # traffic among several OTHER devices
                    a, b = 50 + (i % 4), 60 + (i % 5)
                    fh.write(json.dumps({"id.orig_h": f"192.168.1.{a}", "id.resp_h": f"192.168.1.{b}",
                                         "ts": i}) + "\n")
            self.assertTrue(discover.is_tap(log, {ME})["tap"])

    def test_is_tap_false_on_normal_switch(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "conn.log"
            with open(log, "w") as fh:
                for i in range(30):                                 # all traffic involves this PC
                    fh.write(json.dumps({"id.orig_h": ME, "id.resp_h": "8.8.8.8", "ts": i}) + "\n")
            self.assertFalse(discover.is_tap(log, {ME})["tap"])


class TestNetcheck(unittest.TestCase):
    WIFI = ("*:Casa:WPA2:6:80:AA\\:BB\\:CC\\:00\\:00\\:01\n"
            " :Vicino:WPA2:11:40:AA\\:BB\\:CC\\:00\\:00\\:02\n")

    def test_open_network_is_danger(self):
        f = nc.wifi_findings("*:HotelFree::6:70:AA\\:BB\\:CC\\:00\\:00\\:09\n")
        self.assertEqual(f[0]["level"], nc.DANGER)
        self.assertIn("aperta", f[0]["title"])

    def test_protected_network_ok(self):
        f = nc.wifi_findings(self.WIFI)
        self.assertEqual(f[0]["level"], nc.OK)

    def test_evil_twin_same_ssid_two_securities(self):
        wifi = ("*:Casa:WPA2:6:80:AA\\:BB\\:CC\\:00\\:00\\:01\n"
                " :Casa::11:90:DE\\:AD\\:BE\\:EF\\:00\\:09\n")       # same name, now open
        f = nc.wifi_findings(wifi)
        self.assertTrue(any(x["level"] == nc.DANGER and "gemella" in x["detail"] for x in f))

    def test_same_ssid_same_security_is_not_flagged(self):
        wifi = ("*:Casa:WPA2:6:80:AA\\:BB\\:CC\\:00\\:00\\:01\n"
                " :Casa:WPA2:11:90:AA\\:BB\\:CC\\:00\\:00\\:0a\n")   # mesh: fine
        f = nc.wifi_findings(wifi)
        self.assertFalse(any("gemella" in x["detail"] for x in f))

    def test_dns_hijack_detected(self):
        f = nc.dns_findings("nope.invalid-xyz.com", ["3.4.5.6"])
        self.assertEqual(f[0]["level"], nc.DANGER)

    def test_dns_ok_when_nxdomain(self):
        f = nc.dns_findings("nope.invalid-xyz.com", [])
        self.assertEqual(f[0]["level"], nc.OK)

    def test_weak_wep_flagged(self):
        f = nc.wifi_findings("*:Vecchia:WEP:6:70:AA\\:BB\\:CC\\:00\\:00\\:01\n")
        self.assertEqual(f[0]["level"], nc.WARN)


class TestInspectSummary(unittest.TestCase):
    def test_per_device_groups_by_local_device(self):
        conns = [{"id.orig_h": CAM, "id.resp_h": "93.184.216.34", "id.resp_p": 443,
                  "orig_bytes": 1000, "resp_bytes": 5000, "ts": 100},
                 {"id.orig_h": CAM, "id.resp_h": "8.8.8.8", "id.resp_p": 53,
                  "orig_bytes": 60, "resp_bytes": 120, "ts": 101},
                 {"id.orig_h": ME, "id.resp_h": "1.1.1.1", "id.resp_p": 443, "ts": 102}]
        dns = [{"id.orig_h": CAM, "query": "telemetry.example.com", "ts": 100}]
        out = insp.per_device(conns, dns, {ME}, GW, 0, 1000)
        self.assertEqual(len(out), 1)                                # self is excluded
        d = out[0]
        self.assertEqual(d["ip"], CAM)
        self.assertEqual(d["conns"], 2)
        self.assertEqual(d["ext_peers"], 2)
        self.assertIn(443, d["top_ports"])
        self.assertEqual(d["dns_names"], ["telemetry.example.com"])
        self.assertIn("connessioni", insp.device_line(d))

    def test_window_excludes_old_records(self):
        conns = [{"id.orig_h": CAM, "id.resp_h": "9.9.9.9", "ts": 5}]
        self.assertEqual(insp.per_device(conns, [], {ME}, GW, 100, 200), [])


if __name__ == "__main__":
    unittest.main()
