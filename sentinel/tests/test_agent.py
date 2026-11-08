"""Sentinel agent (0.3): playbooks, safety rules, levels, dedupe, execution and undo."""

import gzip
import json
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

from cyberdistro_sentinel import agent as ag
from cyberdistro_sentinel.config import Paths
from cyberdistro_sentinel.rules import Device, Incident
from cyberdistro_sentinel.store import Store

ME, GW, ATT, DNS = "192.168.1.35", "192.168.1.1", "192.168.1.66", "192.168.1.1"


def inc(rule, sev="alta", src=ATT, dst=ME, **facts):
    now = time.time()
    return Incident(key=f"{rule}:{src}:{dst}", rule=rule, level="confermato", severity=sev, src=src, dst=dst,
                    first_ts=now - 30, last_ts=now, facts=facts)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        zeek = d / "zeek"
        zeek.mkdir()
        now = time.time()
        with open(zeek / "conn.log", "w") as fh:
            for p in range(30):
                fh.write(json.dumps({"ts": now - 20, "id.orig_h": ATT, "id.resp_h": ME, "id.resp_p": 1000 + p,
                                     "conn_state": "REJ"}) + "\n")
        with open(zeek / "dns.log", "w") as fh:
            fh.write(json.dumps({"ts": now - 10, "id.orig_h": ATT, "query": "example.invalid"}) + "\n")
        import os
        os.environ["SENTINEL_ZEEK"] = str(zeek)
        self.paths = Paths()
        self.st = Store(d / "s.db")
        self.st.upsert_device("me", Device(mac="aa:aa:aa:aa:aa:35", ip=ME, first_seen=now, last_seen=now, is_self=True))
        self.st.upsert_device("gw", Device(mac="aa:aa:aa:aa:aa:01", ip=GW, first_seen=now, last_seen=now,
                                           is_gateway=True))
        self.st.commit()
        self.agent = ag.Agent(self.st, self.paths)
        # the test host's own routes must not leak into the scenario
        for name, val in (("default_gateway", None), ("local_ips", set())):
            pt = mock.patch.object(ag, name, return_value=val)
            pt.start()
            self.addCleanup(pt.stop)

    def tearDown(self):
        self.st.db.close()
        self.tmp.cleanup()

    def add(self, i):
        self.st.upsert_incident(i)
        self.st.commit()

    def tasks(self, action=None):
        return [t for t in self.st.tasks() if action is None or t["action"] == action]


class TestPlaybooks(Base):
    def test_port_scan_on_this_pc_proposes_block_capture_and_collects_context(self):
        self.add(inc("port_scan", ports=30, window_s=60, dst_role="self"))
        self.agent.step()
        (b,) = self.tasks("block")
        self.assertEqual((b["target"], b["status"]), (ATT, ag.PROPOSTA))
        self.assertEqual(self.tasks("capture")[0]["status"], ag.PROPOSTA)
        (c,) = self.tasks("context")
        self.assertEqual(c["status"], ag.COMPLETATA)
        self.assertEqual(c["result"]["connections"], 30)
        self.assertEqual(c["result"]["failed"], 30)
        self.assertIn("30 connessioni", ag.context_text(c["result"]))

    def test_never_targets_router_self_or_dns(self):
        ctx = {"self_ip": ME, "gateway": GW, "resolvers": {"192.168.1.53"}}
        for ip in (ME, GW, "192.168.1.53", "224.0.0.1", "192.168.1.255", "fe80::1"):
            self.assertFalse(ag.safe_target(ip, ctx)[0], ip)
        self.add(inc("brute_force", src=GW))
        self.agent.step()
        self.assertFalse(self.tasks("block"))

    def test_gateway_arp_spoof_proposes_pin_to_the_real_mac(self):
        self.add(inc("arp_spoof", src=None, dst=GW, ip=GW, old_mac="aa:aa:aa:aa:aa:01",
                     new_mac="de:ad:be:ef:00:01", is_gateway=True))
        self.agent.step()
        (p,) = self.tasks("pin_gateway")
        self.assertEqual(p["params"]["mac"], "aa:aa:aa:aa:aa:01")
        self.assertIn("aa:aa:aa:aa:aa:01", ag.effect(p))

    def test_informational_and_user_activity_get_nothing(self):
        self.add(inc("suricata_alert", sev="bassa", informational=True))
        self.add(inc("own_scan", sev="bassa", src=ME, dst=ATT, by_user=True, kind="porte", ports=100))
        self.agent.step()
        self.assertFalse([t for t in self.tasks() if t["action"] != "context"])

    def test_this_pc_beaconing_blocks_the_server(self):
        self.add(inc("beaconing", sev="media", src=ME, dst="203.0.113.9", count=8, interval_s=60))
        self.agent.step()
        self.assertEqual(self.tasks("block")[0]["target"], "203.0.113.9")

    def test_examine_new_devices_only_on_declared_own_network(self):
        i = inc("new_device", sev="bassa", src="192.168.1.77", dst=None, ip="192.168.1.77", mac="02:00:00:00:00:77")
        self.add(i)
        self.agent.step()
        self.assertFalse(self.tasks("examine"))
        self.st.set_meta("own_network", "aa:aa:aa:aa:aa:01", commit=True)
        self.agent.step()
        self.assertEqual(self.tasks("examine")[0]["target"], "192.168.1.77")


class TestKernelFacts(unittest.TestCase):
    def test_default_gateway_and_local_ips_from_proc(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d) / "route"
            r.write_text("Iface\tDestination\tGateway\tFlags\n"
                         "enp0s3\t00000000\tFE4DA8C0\t0003\nenp0s3\t004DA8C0\t00000000\t0001\n")
            self.assertEqual(ag.default_gateway(str(r)), "192.168.77.254")
            t = Path(d) / "trie"
            t.write_text("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 192.168.77.111\n        /32 host LOCAL\n"
                         "     |-- 192.168.77.255\n        /32 link BROADCAST\n")
            self.assertEqual(ag.local_ips(str(t)), {"192.168.77.111"})


class TestLevelsAndLimits(Base):
    def test_observe_level_only_advises(self):
        self.st.set_meta("agent_level", "osserva", commit=True)
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        self.assertEqual(self.tasks("block")[0]["status"], ag.CONSIGLIO)

    def test_paused_agent_proposes_nothing(self):
        self.st.set_meta("agent_paused", True, commit=True)
        self.add(inc("port_scan", ports=30, window_s=60))
        self.assertEqual(self.agent.step(), 0)
        self.assertFalse(self.tasks())

    def test_no_duplicates_and_rejections_are_remembered(self):
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        self.agent.step()
        self.assertEqual(len(self.tasks("block")), 1)
        ag.reject(self.st, self.tasks("block")[0])
        self.agent.step()
        self.assertEqual(len(self.tasks("block")), 1)

    def test_rate_limit(self):
        for n in range(30):
            self.add(inc("port_scan", src=f"192.168.1.{100 + n}", ports=30, window_s=60))
        self.agent.step()
        self.assertLessEqual(len([t for t in self.tasks() if t["action"] != "context"]), ag.MAX_PER_HOUR)


class TestExecution(Base):
    def setUp(self):
        super().setUp()
        self.calls = []

    def runner(self, code=0, out="ok"):
        def r(cmd, timeout):
            self.calls.append(cmd)
            return code, out
        return r

    def test_approve_block_then_undo(self):
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        b = self.tasks("block")[0]
        t = ag.execute(self.st, b, self.runner(out="Bloccato"), ["pkexec"])
        self.assertEqual(self.calls[-1], ["pkexec", ag.ACTION_HELPER, "block", ATT, "24"])
        self.assertEqual(t["status"], ag.ATTIVA)
        self.assertGreater(t["expires_ts"], time.time() + 23 * 3600)
        t = ag.undo(self.st, t, self.runner(), ["pkexec"])
        self.assertEqual(self.calls[-1], ["pkexec", ag.ACTION_HELPER, "unblock", ATT])
        self.assertEqual(t["status"], ag.ANNULLATA)

    def test_failed_action_is_an_error_and_logged(self):
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        t = ag.execute(self.st, self.tasks("block")[0], self.runner(code=3, out="Rifiutato: è il router"), ["pkexec"])
        self.assertEqual(t["status"], ag.ERRORE)
        self.assertIn("Rifiutato", self.st.agent_logs()[0]["text"])

    def test_active_block_expires(self):
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        t = ag.execute(self.st, self.tasks("block")[0], self.runner(), ["pkexec"])
        self.agent.step(now=time.time() + 25 * 3600)
        self.assertEqual(self.st.task(t["id"])["status"], ag.SCADUTA)

    def test_examine_records_user_scan_and_ports(self):
        self.st.set_meta("own_network", "aa:aa:aa:aa:aa:01", commit=True)
        self.add(inc("new_device", sev="bassa", src="192.168.1.77", dst=None, ip="192.168.1.77"))
        self.agent.step()
        nmap = "23/tcp open telnet\n80/tcp open http\nNmap done: 1 IP address (1 host up)\n"
        t = ag.execute(self.st, self.tasks("examine")[0], self.runner(out=nmap), ["pkexec"])
        self.assertEqual(self.calls[-1][0], "nmap")                 # not privileged
        self.assertEqual(t["result"]["ports"], [23, 80])
        (w,) = self.st.scan_windows()                               # counted as the user's own activity
        self.assertEqual(w[3], "192.168.1.77")

    def test_model_facts_have_no_network_names(self):
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        c = self.tasks("context")[0]
        self.assertEqual(c["result"]["dns_names"], ["example.invalid"])
        f = ag.task_facts(c, None)
        self.assertNotIn("example.invalid", f)

    def test_auto_level_still_proposes_for_the_gui_to_run(self):
        self.st.set_meta("agent_level", "auto", commit=True)
        self.add(inc("port_scan", ports=30, window_s=60))
        self.agent.step()
        self.assertEqual(self.tasks("block")[0]["status"], ag.PROPOSTA)
        self.assertIn("block", ag.AUTO_ACTIONS)
        self.assertNotIn("examine", ag.AUTO_ACTIONS)

    def test_examine_history_line_lists_ports(self):
        self.st.set_meta("own_network", "aa:aa:aa:aa:aa:01", commit=True)
        self.add(inc("new_device", sev="bassa", src="192.168.1.77", dst=None, ip="192.168.1.77"))
        self.agent.step()
        nmap = "23/tcp open telnet\n80/tcp open http\nNmap done: 1 IP address (1 host up)\n"
        ag.execute(self.st, self.tasks("examine")[0], self.runner(out=nmap), ["pkexec"])
        line = self.st.agent_logs()[0]["text"]
        self.assertIn("Porte aperte trovate: 23, 80", line)


if __name__ == "__main__":
    unittest.main()
