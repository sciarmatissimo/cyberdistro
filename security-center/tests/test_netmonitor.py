"""Unit tests for the transparent-bridge network monitor core."""

import json
import unittest

from cyberdistro_sc.tools import netmonitor as nm

LINK = json.dumps([
    {"ifname": "lo", "link_type": "loopback", "operstate": "UNKNOWN", "flags": ["LOOPBACK", "UP"]},
    {"ifname": "eth0", "link_type": "ether", "address": "aa:bb:cc:00:00:01",
     "operstate": "UP", "flags": ["BROADCAST", "LOWER_UP"]},
    {"ifname": "eth1", "link_type": "ether", "address": "aa:bb:cc:00:00:02",
     "operstate": "DOWN", "flags": ["BROADCAST"]},
    {"ifname": "wlan0", "link_type": "ether", "address": "aa:bb:cc:00:00:03",
     "operstate": "UP", "flags": ["BROADCAST", "LOWER_UP"]},
    {"ifname": "docker0", "link_type": "ether", "address": "02:42:00:00:00:01",
     "operstate": "DOWN", "flags": []},
    {"ifname": "br-existing", "link_type": "ether", "operstate": "UP",
     "linkinfo": {"info_kind": "bridge"}},
    {"ifname": "eth2", "link_type": "ether", "address": "aa:bb:cc:00:00:04",
     "operstate": "UP", "master": "br-existing", "flags": ["LOWER_UP"]},
])
ADDR = json.dumps([
    {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.5", "prefixlen": 24}]},
    {"ifname": "wlan0", "addr_info": [{"family": "inet6", "local": "fe80::1", "prefixlen": 64}]},
])
ROUTE = json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"}])


class TestInterfaces(unittest.TestCase):
    def test_parse_filters_and_flags(self):
        ifs = nm.parse_interfaces(LINK, ADDR, ROUTE, is_wireless=lambda n: n == "wlan0")
        names = [i.name for i in ifs]
        self.assertIn("eth0", names)
        self.assertIn("eth1", names)
        self.assertIn("wlan0", names)
        self.assertNotIn("lo", names)          # loopback
        self.assertNotIn("docker0", names)     # virtual
        self.assertNotIn("br-existing", names)  # a bridge itself
        self.assertNotIn("eth2", names)        # already a bridge port
        by = {i.name: i for i in ifs}
        self.assertTrue(by["eth0"].carrier and by["eth0"].is_default_route)
        self.assertEqual(by["eth0"].addresses, ["192.168.1.5/24"])
        self.assertTrue(by["eth0"].has_ip)
        self.assertEqual(by["wlan0"].kind, "wifi")
        self.assertFalse(by["eth1"].carrier)
        self.assertFalse(by["eth1"].is_default_route)

    def test_titles_bilingual(self):
        i = nm.Interface(name="eth0", kind="wired", carrier=True)
        self.assertIn("cavo collegato", i.title("it"))
        self.assertIn("cable connected", i.title("en"))


class TestPlans(unittest.TestCase):
    def test_bridge_plans_are_argv_lists(self):
        c = nm.plan_bridge_create("eth0", "eth1")
        self.assertEqual(c, ["pkexec", nm.BRIDGE_HELPER, "create", "eth0", "eth1"])
        self.assertEqual(nm.plan_bridge_create("eth0", "eth1", privileged=False),
                         [nm.BRIDGE_HELPER, "create", "eth0", "eth1"])
        self.assertIn("--force", nm.plan_bridge_create("eth0", "eth1", force=True))
        self.assertEqual(nm.plan_bridge_destroy()[1:], [nm.BRIDGE_HELPER, "destroy"])

    def test_capture_plans(self):
        w = nm.plan_wireshark()
        self.assertEqual(w[:4], ["wireshark", "-i", "br0", "-k"])
        self.assertIn("tls.handshake.extensions_server_name", w[-1])
        ts = nm.plan_tshark_summary()
        self.assertEqual(ts[:4], ["tshark", "-l", "-n", "-i"])
        for f in nm.TSHARK_FIELDS:
            self.assertIn(f, ts)


SAMPLE = "\n".join([
    # eth.src  ip.src       ip.dst        dns            sni                http.host
    "aa:bb:cc:00:00:11\t192.168.1.23\t8.8.8.8\texample.com\t\t",
    "aa:bb:cc:00:00:11\t192.168.1.23\t93.184.216.34\t\texample.com\t",
    "aa:bb:cc:00:00:22\t192.168.1.50\t1.1.1.1\t\tcdn.shop.net\t",
    "aa:bb:cc:00:00:22\t192.168.1.50\t1.1.1.1\t\t\tplain.example.org",
    "aa:bb:cc:00:00:11\t192.168.1.23\t2.2.2.2\tEXAMPLE.com.\t\t",   # dup, case/dot
    "\t\t\t\t\t",                                                    # empty row ignored
])


class TestSummary(unittest.TestCase):
    def test_aggregates_devices_and_sites(self):
        s = nm.parse_summary(SAMPLE)
        devs = {d.ip: d for d in s.top_devices()}
        self.assertEqual(set(devs), {"192.168.1.23", "192.168.1.50"})
        self.assertEqual(devs["192.168.1.23"].packets, 3)
        self.assertEqual(devs["192.168.1.23"].mac, "aa:bb:cc:00:00:11")
        # sites normalized (case + trailing dot collapse example.com)
        sites = {s2.name: s2 for s2 in s.top_sites()}
        self.assertIn("example.com", sites)
        self.assertIn("cdn.shop.net", sites)
        self.assertIn("plain.example.org", sites)
        self.assertEqual(sites["example.com"].hits, 3)  # dns + sni + dup
        self.assertIn("192.168.1.23", sites["example.com"].clients)
        # device carries the set of sites it contacted
        self.assertIn("example.com", devs["192.168.1.23"].sites)
        self.assertEqual(devs["192.168.1.50"].sites, {"cdn.shop.net", "plain.example.org"})

    def test_incremental_feed_matches_batch(self):
        s = nm.TrafficSummary()
        for line in SAMPLE.splitlines():
            s.feed_line(line)
        self.assertEqual(sum(d.packets for d in s.devices.values()), 5)

    def test_to_dict_serializable(self):
        s = nm.parse_summary(SAMPLE)
        d = s.top_devices()[0].to_dict()
        self.assertIn("sites", d)
        self.assertIsInstance(d["sites"], list)
        json.dumps([x.to_dict() for x in s.top_sites()])  # must not raise


if __name__ == "__main__":
    unittest.main()
