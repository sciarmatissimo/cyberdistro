"""Sentinel 0.2: own activity vs attacks, roles, informational signatures, port
knowledge and the network fact sheet. Reproduces the case seen on a real Dell
(Lite 0.1.0): the user examined a device with Nmap from the Security Center and
got "someone is probing ports", "suspicious traffic" from the router and a
burst of "new device" alarms."""

import tempfile
import unittest
from pathlib import Path

from cyberdistro_sentinel.assistant import action_plan, answer_question, network_facts
from cyberdistro_sentinel.events import Event
from cyberdistro_sentinel.knowledge import parse_nmap_open, ports_from_result, summarize_ports
from cyberdistro_sentinel.rules import LOW, MEDIUM, Correlator
from cyberdistro_sentinel.store import Store
from cyberdistro_sentinel.templates import card

ME, GW, CAM, OTHER = "192.168.179.35", "192.168.179.1", "192.168.179.20", "192.168.179.66"
T0 = 1_800_000_000.0


def net(c):
    c.process(Event(ts=T0, engine="sensor", kind="net", ref="s:0", data={"gateway": GW, "self_ip": ME,
                                                                          "self_mac": "aa:bb:cc:00:00:35"}))


def scan(c, src, dst, t, n=100):
    for p in range(n):
        c.process(Event(ts=t + p * 0.05, engine="zeek", kind="conn", ref=f"z:{src}:{p}", src=src, dst=dst,
                        dport=1000 + p, data={"state": "REJ"}))


def as_dict(i):
    return {"key": i.key, "rule": i.rule, "level": i.level, "severity": i.severity, "src": i.src, "dst": i.dst,
            "first_ts": i.first_ts, "last_ts": i.last_ts, "count": i.count, "facts": i.facts,
            "evidence": i.evidence, "status": "aperto"}


class TestOwnActivity(unittest.TestCase):
    def test_scan_started_by_user_is_information(self):
        c = Correlator()
        net(c)
        c.set_user_activity([(T0 + 300, T0 + 330, "scansione dispositivo", CAM)])
        scan(c, ME, CAM, T0 + 301)
        rules = {i.rule for i in c.incidents.values()}
        self.assertNotIn("port_scan", rules)
        own = [i for i in c.incidents.values() if i.rule == "own_scan"]
        self.assertEqual(len(own), 1)
        self.assertTrue(own[0].facts["by_user"])
        self.assertEqual(own[0].severity, LOW)
        self.assertEqual(card(as_dict(own[0]))["title"], "Scansione avviata da te")

    def test_scan_from_this_pc_not_started_by_user_is_suspicious(self):
        c = Correlator()
        net(c)
        scan(c, ME, CAM, T0 + 301)
        own = [i for i in c.incidents.values() if i.rule == "own_scan"]
        self.assertEqual(len(own), 1)
        self.assertFalse(own[0].facts["by_user"])
        self.assertEqual(own[0].severity, MEDIUM)
        self.assertIn("non l'hai chiesto", card(as_dict(own[0]))["title"])

    def test_user_window_does_not_hide_other_attackers(self):
        c = Correlator()
        net(c)
        c.set_user_activity([(T0 + 300, T0 + 330, "scansione dispositivo", CAM)])
        scan(c, OTHER, ME, T0 + 301)                # someone else scans this PC meanwhile
        ps = [i for i in c.incidents.values() if i.rule == "port_scan"]
        self.assertEqual(len(ps), 1)
        self.assertEqual(ps[0].src, OTHER)
        self.assertEqual(ps[0].facts.get("dst_role"), "self")

    def test_informational_signature_from_router(self):
        c = Correlator()
        net(c)
        c.process(Event(ts=T0 + 400, engine="suricata", kind="alert", ref="s:1", src=GW, dst=ME,
                        data={"signature": "ET DNS Standard query response, Name Error",
                              "category": "Not Suspicious Traffic", "signature_id": 2001117, "severity": 3}))
        (i,) = [x for x in c.incidents.values() if x.rule == "suricata_alert"]
        self.assertEqual(i.severity, LOW)
        cd = card(as_dict(i))
        self.assertIn("il router (192.168.179.1)", cd["what"])
        self.assertIn("questo PC (192.168.179.35)", cd["what"])
        self.assertEqual(cd["todo"], "Non serve fare nulla.")

    def test_real_signature_from_router_says_do_not_block(self):
        c = Correlator()
        net(c)
        c.process(Event(ts=T0 + 400, engine="suricata", kind="alert", ref="s:1", src=GW, dst=ME,
                        data={"signature": "ET EXPLOIT x", "category": "Attempted Administrator Privilege Gain",
                              "signature_id": 1, "severity": 1}))
        (i,) = [x for x in c.incidents.values() if x.rule == "suricata_alert"]
        self.assertIn("non bloccarlo", card(as_dict(i))["todo"])

    def test_devices_answering_users_scan(self):
        c = Correlator()
        net(c)
        c.set_user_activity([(T0 + 300, T0 + 360, "scansione rete", "192.168.179.0/24")])
        c.process(Event(ts=T0 + 310, engine="sensor", kind="arp", ref="s:2", src=CAM,
                        data={"mac": "00:11:22:33:44:55"}))
        (i,) = [x for x in c.incidents.values() if x.rule == "new_device"]
        self.assertTrue(i.facts["found_by_scan"])
        self.assertEqual(card(as_dict(i))["title"], "Dispositivo trovato dalla tua scansione")

    def test_ntp_is_not_beaconing(self):
        c = Correlator()
        net(c)
        for k in range(10):
            c.process(Event(ts=T0 + k * 64, engine="zeek", kind="conn", ref=f"n{k}", src=ME, dst="162.159.200.1",
                            dport=123, data={"state": "SF", "orig_bytes": 48}))
        self.assertFalse([i for i in c.incidents.values() if i.rule == "beaconing"])

    def test_store_scan_windows_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(Path(d) / "s.db")
            aid = st.log_action("scansione dispositivo", CAM, "in corso")
            st.finish_action(aid, "porte aperte: 23, 80")
            (w,) = st.scan_windows()
            self.assertEqual(w[2:], ("scansione dispositivo", CAM))
            self.assertIsNotNone(w[1])


class TestKnowledgeAndAssistant(unittest.TestCase):
    NMAP = ("Nmap scan report for 192.168.179.20\nPORT     STATE SERVICE\n23/tcp   open  telnet\n"
            "80/tcp   open  http\n554/tcp  closed rtsp\nNmap done: 1 IP address (1 host up)\n")

    def test_parse_and_explain_ports(self):
        self.assertEqual(parse_nmap_open(self.NMAP), [23, 80])
        txt = summarize_ports([80, 23])
        self.assertTrue(txt.startswith("Porta 23: Telnet"))      # highest risk first
        self.assertIn("rischio alto", txt)
        self.assertEqual(ports_from_result("porte aperte: 23, 80"), [23, 80])

    def _world(self):
        devices = [{"ip": ME, "mac": "aa:bb:cc:00:00:35", "is_self": 1, "is_gateway": 0, "new": 0},
                   {"ip": GW, "mac": "aa:bb:cc:00:00:01", "is_self": 0, "is_gateway": 1, "new": 0},
                   {"ip": CAM, "mac": "02:11:22:33:44:55", "is_self": 0, "is_gateway": 0, "new": 1}]
        actions = [{"ts": T0, "end_ts": T0 + 20, "action": "scansione dispositivo", "target": CAM,
                    "result": "porte aperte: 23, 80"}]
        return {"colour": "verde"}, [], devices, actions

    def test_question_about_an_address(self):
        st, inc, dev, act = self._world()
        a = answer_question(f"chi è {CAM}?", st, inc, dev, actions=act)
        self.assertIn("Telnet", a)
        a = answer_question(f"chi è {ME}?", st, inc, dev, actions=act)
        self.assertIn("Questo PC", a)

    def test_how_many_and_os_questions(self):
        st, inc, dev, act = self._world()
        self.assertIn("Router: 1", answer_question("quanti router ci sono?", st, inc, dev, actions=act))
        self.assertIn("sistema operativo", answer_question("quanti dispositivi windows ci sono?", st, inc, dev))

    def test_action_plan_puts_risky_ports_before_hygiene(self):
        st, inc, dev, act = self._world()
        plan = action_plan(st, inc, dev, act)
        self.assertTrue(plan[0].startswith("[Importante] 192.168.179.20, porta 23"))
        self.assertTrue(plan[-1].startswith("[Buona pratica]"))
        a = answer_question("Cosa devo fare adesso?", st, inc, dev, actions=act)
        self.assertIn("porta 23", a)

    def test_network_facts_have_roles_ports_and_no_announced_names(self):
        st, inc, dev, act = self._world()
        dev[2]["hostname"] = "evil-name-from-network"
        f = network_facts(st, inc, dev, act)
        self.assertIn(f"Questo PC (dove gira Sentinel): {ME}", f)
        self.assertIn(f"Router: {GW}", f)
        self.assertIn("Telnet", f)
        self.assertNotIn("evil-name", f)


if __name__ == "__main__":
    unittest.main()
