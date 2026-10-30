"""Unit tests for the beginner «Esplora» module (pure parsers + gating)."""

import json
import os
import subprocess
import tempfile
import unittest
import unittest.mock

from cyberdistro_sc.core.authorization import AuthorizationError
from cyberdistro_sc.tools import explore as ex

IP_ADDR = json.dumps([
    {"ifname": "lo", "operstate": "UNKNOWN",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifname": "wlan0", "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "192.168.1.42", "prefixlen": 24, "scope": "global"},
                   {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]},
    {"ifname": "eth0", "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "10.3.7.9", "prefixlen": 8, "scope": "global"}]},
    {"ifname": "docker0", "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global"}]},
    {"ifname": "eth1", "operstate": "DOWN",
     "addr_info": [{"family": "inet", "local": "10.9.9.9", "prefixlen": 24, "scope": "global"}]},
])

IP_ROUTE = json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0", "flags": []}])

IP_NEIGH = json.dumps([
    {"dst": "192.168.1.1", "dev": "wlan0", "lladdr": "a4:2b:b0:11:22:33", "state": ["REACHABLE"]},
    {"dst": "192.168.1.23", "dev": "wlan0", "lladdr": "3c:22:fb:aa:bb:cc", "state": ["STALE"]},
    {"dst": "192.168.1.99", "dev": "wlan0", "state": ["FAILED"]},
    {"dst": "fe80::2", "dev": "wlan0", "lladdr": "00:11:22:33:44:55", "state": ["REACHABLE"]},
])

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn -oX - 192.168.1.0/24">
<host><status state="up" reason="arp-response"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <address addr="A4:2B:B0:11:22:33" addrtype="mac" vendor="AVM Audiovisuelles Marketing und Computersysteme"/>
  <hostnames><hostname name="fritz.box" type="PTR"/></hostnames></host>
<host><status state="up" reason="syn-ack"/>
  <address addr="192.168.1.23" addrtype="ipv4"/>
  <hostnames><hostname name="Giovannis-iPhone" type="PTR"/></hostnames></host>
<host><status state="up" reason="syn-ack"/>
  <address addr="192.168.1.42" addrtype="ipv4"/><hostnames/></host>
<host><status state="down" reason="no-response"/>
  <address addr="192.168.1.50" addrtype="ipv4"/></host>
<host><status state="up" reason="syn-ack"/>
  <address addr="192.168.1.77" addrtype="ipv4"/>
  <hostnames><hostname name="HP-LaserJet-M15" type="PTR"/></hostnames></host>
</nmaprun>"""

BT_DEVICES = """Device 44:55:66:77:88:99 Giovanni's AirPods
Device AA:BB:CC:DD:EE:FF AA-BB-CC-DD-EE-FF
Device 11:22:33:44:55:66 Galaxy Watch4
"""

BT_INFO_AIRPODS = """Device 44:55:66:77:88:99 (public)
\tName: Giovanni's AirPods
\tAlias: Giovanni's AirPods
\tClass: 0x00240418
\tIcon: audio-headset
\tPaired: yes
\tBonded: yes
\tTrusted: yes
\tBlocked: no
\tConnected: no
\tLegacyPairing: no
\tUUID: Audio Sink                (0000110b-0000-1000-8000-00805f9b34fb)
\tUUID: A/V Remote Control        (0000110e-0000-1000-8000-00805f9b34fb)
\tRSSI: -58
\tBattery Percentage: 0x55 (85)
"""

BT_INFO_RANDOM = """Device AA:BB:CC:DD:EE:FF (random)
\tAlias: AA-BB-CC-DD-EE-FF
\tPaired: no
\tTrusted: no
\tBlocked: no
\tConnected: no
\tLegacyPairing: no
\tRSSI: -81
"""


def fake_run_factory(table):
    """Build a runner that answers from a {argv_prefix: stdout} table."""
    calls = []

    def run(argv, timeout=30.0):
        calls.append(list(argv))
        for prefix, out in table.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return subprocess.CompletedProcess(argv, 0, out, "")
        return subprocess.CompletedProcess(argv, 1, "", "no fake output")
    run.calls = calls
    return run


class TestLocalNetworks(unittest.TestCase):
    def test_parse_ip_addr_filters_and_caps(self):
        nets = ex.parse_ip_addr(IP_ADDR, is_wireless=lambda i: i == "wlan0")
        names = {n.interface: n for n in nets}
        self.assertIn("wlan0", names)
        self.assertIn("eth0", names)
        self.assertNotIn("lo", names)        # loopback skipped
        self.assertNotIn("docker0", names)   # virtual bridge skipped
        self.assertNotIn("eth1", names)      # link down skipped
        self.assertEqual(names["wlan0"].kind, "wifi")
        self.assertEqual(names["wlan0"].cidr, "192.168.1.0/24")
        self.assertFalse(names["wlan0"].capped)
        # a /8 is capped to the /24 around our address
        self.assertEqual(names["eth0"].cidr, "10.3.7.0/24")
        self.assertTrue(names["eth0"].capped)

    def test_gateways_and_ssid(self):
        self.assertEqual(ex.parse_ip_route_gateways(IP_ROUTE), {"wlan0": "192.168.1.1"})
        self.assertEqual(ex.parse_iw_ssid("Connected to aa:bb (on wlan0)\n\tSSID: CasaMia 5G\n\tfreq: 5180"),
                         "CasaMia 5G")
        self.assertEqual(ex.parse_iw_ssid("Not connected."), "")

    def test_local_networks_orders_default_route_first(self):
        run = fake_run_factory({
            ("ip", "-j", "addr"): IP_ADDR,
            ("ip", "-j", "route"): IP_ROUTE,
            ("iw", "dev", "wlan0", "link"): "\tSSID: CasaMia\n",
        })
        with unittest.mock.patch.object(ex, "_is_wireless", lambda i: i == "wlan0"):
            nets = ex.local_networks(run)
        self.assertEqual(nets[0].interface, "wlan0")
        self.assertEqual(nets[0].gateway, "192.168.1.1")
        self.assertEqual(nets[0].ssid, "CasaMia")
        self.assertEqual(nets[0].title, "Wi‑Fi «CasaMia»")


class TestParsers(unittest.TestCase):
    def test_parse_nmap_hosts_only_up(self):
        hosts = ex.parse_nmap_hosts(NMAP_XML)
        addrs = [h["address"] for h in hosts]
        self.assertEqual(addrs, ["192.168.1.1", "192.168.1.23", "192.168.1.42", "192.168.1.77"])
        self.assertEqual(hosts[0]["mac"], "A4:2B:B0:11:22:33")
        self.assertIn("AVM", hosts[0]["vendor"])
        self.assertEqual(hosts[1]["hostname"], "Giovannis-iPhone")
        self.assertEqual(ex.parse_nmap_hosts(""), [])
        self.assertEqual(ex.parse_nmap_hosts("<broken"), [])

    def test_parse_ip_neigh(self):
        n = ex.parse_ip_neigh(IP_NEIGH)
        self.assertEqual(n["192.168.1.1"], "A4:2B:B0:11:22:33")
        self.assertEqual(n["192.168.1.23"], "3C:22:FB:AA:BB:CC")
        self.assertNotIn("192.168.1.99", n)   # FAILED
        self.assertNotIn("fe80::2", n)        # IPv6 ignored

    def test_bluetoothctl_parsers(self):
        devs = ex.parse_bluetoothctl_devices(BT_DEVICES)
        self.assertEqual(devs[0], ("44:55:66:77:88:99", "Giovanni's AirPods"))
        self.assertEqual(devs[1], ("AA:BB:CC:DD:EE:FF", ""))   # name == MAC → empty
        info = ex.parse_bluetoothctl_info(BT_INFO_AIRPODS)
        self.assertEqual(info["Name"], "Giovanni's AirPods")
        self.assertEqual(info["Icon"], "audio-headset")
        self.assertEqual(info["Paired"], "yes")
        self.assertEqual(info["RSSI"], "-58")
        self.assertEqual(len(info["uuids"]), 2)
        self.assertEqual(ex._bt_kind(info), "audio")
        self.assertEqual(ex._bt_kind({"Name": "Galaxy Watch4"}), "wearable")


class TestClassifyAndVendor(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(ex.classify(is_self=True), "self")
        self.assertEqual(ex.classify(is_gateway=True), "router")
        self.assertEqual(ex.classify("Giovannis-iPhone"), "phone")
        self.assertEqual(ex.classify("HP-LaserJet-M15"), "printer")
        self.assertEqual(ex.classify("", "Espressif Inc."), "iot")
        self.assertEqual(ex.classify("", "Apple, Inc."), "computer")
        self.assertEqual(ex.classify("", ""), "unknown")
        self.assertEqual(ex.icon_for("phone"), "smartphone")
        self.assertEqual(ex.icon_for("nope"), ex.icon_for("unknown"))
        # Papirus (shipped in the ISO) has "phone"/"network-modem", so they
        # must be among the candidates; the primary name stays first.
        self.assertEqual(ex.icon_candidates("phone")[0], "smartphone")
        self.assertIn("phone", ex.icon_candidates("phone"))
        self.assertIn("network-modem", ex.icon_candidates("router"))
        for kind in ex.KINDS:
            self.assertTrue(ex.icon_candidates(kind), kind)

    def test_lookup_vendor_with_db_and_random_mac(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# nmap oui\nA42BB0 AVM GmbH\n3C22FB Apple, Inc.\n")
            path = fh.name
        try:
            db = ex.load_oui_db(path)
            self.assertEqual(ex.lookup_vendor("a4:2b:b0:11:22:33", db), "AVM GmbH")
            self.assertEqual(ex.lookup_vendor("3C:22:FB:00:00:01", db), "Apple, Inc.")
            # locally administered (bit 0x02 set) → randomised, no vendor
            self.assertEqual(ex.lookup_vendor("02:FC:00:00:00:05", db), "")
            self.assertEqual(ex.lookup_vendor("", db), "")
        finally:
            os.unlink(path)


class TestScanGating(unittest.TestCase):
    def setUp(self):
        self.net = ex.LocalNetwork(interface="wlan0", kind="wifi", address="192.168.1.42",
                                   cidr="192.168.1.0/24", gateway="192.168.1.1", ssid="CasaMia")
        self.run = fake_run_factory({
            ("nmap",): NMAP_XML,
            ("ip", "-j", "neigh"): IP_NEIGH,
        })
        self.db = {"3C22FB": "Apple, Inc.", "A42BB0": "AVM GmbH"}

    def test_unconfirmed_is_refused_and_runs_nothing(self):
        auth = ex.local_authorization(self.net, "io", confirmed=False)
        with self.assertRaises(AuthorizationError):
            ex.scan_network(self.net, auth, run=self.run, oui_db=self.db)
        self.assertEqual(self.run.calls, [])

    def test_confirmed_scan_builds_devices(self):
        auth = ex.local_authorization(self.net, "io", confirmed=True)
        plan, proc, devices = ex.scan_network(self.net, auth, run=self.run, oui_db=self.db)
        self.assertEqual(plan.argv[:3], ["nmap", "-sn", "-T3"])
        self.assertEqual(plan.argv[-1], "192.168.1.0/24")
        self.assertEqual(proc.returncode, 0)
        kinds = {d.address: d.kind for d in devices}
        self.assertEqual(kinds["192.168.1.42"], "self")
        self.assertEqual(kinds["192.168.1.1"], "router")
        self.assertEqual(kinds["192.168.1.23"], "phone")
        self.assertEqual(kinds["192.168.1.77"], "printer")
        # self first, router second
        self.assertEqual([d.kind for d in devices][:2], ["self", "router"])
        # MAC from neigh table + vendor from OUI db when nmap gave none
        iphone = next(d for d in devices if d.address == "192.168.1.23")
        self.assertEqual(iphone.mac, "3C:22:FB:AA:BB:CC")
        self.assertEqual(iphone.vendor, "Apple, Inc.")
        self.assertEqual(iphone.icon, "smartphone")
        self.assertEqual(iphone.display_name, "Giovannis-iPhone")
        self.assertIn("icon", iphone.to_dict())

    def test_scope_mismatch_refused(self):
        other = ex.LocalNetwork(interface="eth0", kind="ethernet", address="10.0.0.5",
                                cidr="10.0.0.0/24")
        auth = ex.local_authorization(self.net, "io", confirmed=True)   # scope = 192.168.1.0/24
        with self.assertRaises(AuthorizationError):
            ex.scan_network(other, auth, run=self.run)

    def test_bluetooth_scan_with_fake_bluez(self):
        run = fake_run_factory({
            ("bluetoothctl", "list"): "Controller 00:1A:7D:DA:71:13 cyberdistro [default]\n",
            ("bluetoothctl", "power"): "Changing power on succeeded\n",
            ("bluetoothctl", "--timeout"): "Discovery started\n",
            ("bluetoothctl", "devices"): BT_DEVICES,
            ("bluetoothctl", "info", "44:55:66:77:88:99"): BT_INFO_AIRPODS,
            ("bluetoothctl", "info", "AA:BB:CC:DD:EE:FF"): BT_INFO_RANDOM,
            ("bluetoothctl", "info", "11:22:33:44:55:66"): "Device 11:22:33:44:55:66 (public)\n\tName: Galaxy Watch4\n\tIcon: phone\n",
        })
        with unittest.mock.patch.object(ex.shutil, "which", lambda x: "/usr/bin/bluetoothctl"):
            plan, devices, err = ex.scan_bluetooth(seconds=3, run=run, oui_db={})
        self.assertEqual(err, "")
        self.assertEqual(plan.argv, ["bluetoothctl", "--timeout", "3", "scan", "on"])
        by_mac = {d.mac: d for d in devices}
        self.assertEqual(by_mac["44:55:66:77:88:99"].kind, "audio")
        self.assertEqual(by_mac["44:55:66:77:88:99"].details["batteria"], "0x55 (85)")
        self.assertEqual(by_mac["AA:BB:CC:DD:EE:FF"].kind, "unknown")
        self.assertEqual(by_mac["AA:BB:CC:DD:EE:FF"].display_name, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(by_mac["11:22:33:44:55:66"].kind, "phone")   # Icon wins over name
        # never pairs/connects: only list/power/scan/devices/info were invoked
        verbs = {c[1] for c in run.calls if c[0] == "bluetoothctl"}
        self.assertTrue(verbs <= {"list", "power", "--timeout", "devices", "info"})

    def test_bluetooth_unavailable_is_reported_not_faked(self):
        with unittest.mock.patch.object(ex.shutil, "which", lambda x: None):
            plan, devices, err = ex.scan_bluetooth(run=fake_run_factory({}))
        self.assertEqual(devices, [])
        self.assertIn("bluez", err)




if __name__ == "__main__":
    unittest.main()
