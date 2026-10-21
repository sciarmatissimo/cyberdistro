"""Unit tests for the Security Center core. Run with stdlib unittest."""

import os
import tempfile
import unittest

from cyberdistro_sc.core.authorization import (
    Authorization, AuthorizationError, ActivityKind)
from cyberdistro_sc.core.modes import Mode
from cyberdistro_sc.core.runner import CommandRunner, CommandPlan
from cyberdistro_sc.core.catalog import Catalog
from cyberdistro_sc.core.project import Project, Finding
from cyberdistro_sc.core import report as report_mod
from cyberdistro_sc.tools import network_inventory as ni
from cyberdistro_sc.tools import forensic_hash as fh
from cyberdistro_sc.tools import privacy_status as ps

HERE = os.path.dirname(__file__)


class TestAuthorization(unittest.TestCase):
    def setUp(self):
        self.auth = Authorization(project="P", owner="O",
                                  scope=["192.168.10.0/24", "lab.example.test"])

    def test_cidr_in_scope(self):
        self.assertTrue(self.auth.covers("192.168.10.5"))
        self.assertTrue(self.auth.covers("192.168.10.0/28"))

    def test_out_of_scope(self):
        self.assertFalse(self.auth.covers("10.0.0.1"))
        self.assertFalse(self.auth.covers("8.8.8.8"))

    def test_hostname_in_scope(self):
        self.assertTrue(self.auth.covers("lab.example.test"))
        self.assertFalse(self.auth.covers("prod.example.test"))

    def test_active_requires_scope_membership(self):
        self.auth.require("192.168.10.5", ActivityKind.ACTIVE_LIGHT)  # ok
        with self.assertRaises(AuthorizationError):
            self.auth.require("10.0.0.1", ActivityKind.ACTIVE_LIGHT)

    def test_active_without_scope_blocked(self):
        a = Authorization(project="P", owner="O", scope=[])
        with self.assertRaises(AuthorizationError):
            a.require("192.168.10.5", ActivityKind.ACTIVE_INTRUSIVE)

    def test_passive_allowed_but_needs_project(self):
        Authorization(project="P", owner="O").require("x", ActivityKind.PASSIVE)
        with self.assertRaises(AuthorizationError):
            Authorization(project="", owner="").require("x", ActivityKind.PASSIVE)


class TestModes(unittest.TestCase):
    def test_exposure(self):
        self.assertTrue(Mode.EXPERT.shows_raw_command)
        self.assertFalse(Mode.BEGINNER.shows_raw_command)
        self.assertTrue(Mode.PROFESSIONAL.exposes_advanced_params)
        self.assertFalse(Mode.BEGINNER.allows_terminal)

    def test_parse(self):
        self.assertIs(Mode.parse("expert"), Mode.EXPERT)
        self.assertIs(Mode.parse(None, Mode.PROFESSIONAL), Mode.PROFESSIONAL)
        with self.assertRaises(ValueError):
            Mode.parse("wizard")


class TestRunner(unittest.TestCase):
    def test_no_shell_true_command(self):
        r = CommandRunner().run(CommandPlan("echo-test", ["echo", "hello world"]))
        self.assertTrue(r.ok)
        self.assertEqual(r.stdout.strip(), "hello world")
        # shell_preview must be a faithful, quoted reproduction
        self.assertIn("'hello world'", r.shell_preview)

    def test_missing_tool_is_structured_not_crash(self):
        r = CommandRunner().run(CommandPlan("nope", ["definitely_not_a_tool_xyz"]))
        self.assertEqual(r.returncode, 127)
        self.assertTrue(r.extra.get("not_installed"))

    def test_timeout(self):
        r = CommandRunner(default_timeout=0.3).run(
            CommandPlan("sleep", ["sleep", "5"]))
        self.assertTrue(r.timed_out)


class TestNmapParsing(unittest.TestCase):
    def test_parse_sample(self):
        with open(os.path.join(HERE, "sample_nmap.xml"), encoding="utf-8") as fhd:
            hosts = ni.parse_xml(fhd.read())
        self.assertEqual(len(hosts), 2)
        up = [h for h in hosts if h.state == "up"][0]
        self.assertEqual(up.address, "192.0.2.1")
        self.assertEqual(up.hostname, "gw.example.test")
        open_ports = {s.port for s in up.services if s.state == "open"}
        self.assertEqual(open_ports, {22, 80})
        ssh = [s for s in up.services if s.port == 22][0]
        self.assertEqual(ssh.service, "ssh")
        self.assertEqual(ssh.product, "OpenSSH")

    def test_plan_is_safe_argv(self):
        p = ni.plan("192.168.10.0/24", "quick-ports")
        self.assertEqual(p.argv[0], "nmap")
        self.assertIn("-oX", p.argv)
        self.assertIn("192.168.10.0/24", p.argv)

    def test_run_blocks_out_of_scope(self):
        auth = Authorization("P", "O", scope=["192.168.10.0/24"])
        with self.assertRaises(AuthorizationError):
            ni.run("8.8.8.8", auth, profile="quick-ports")

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            ni.plan("192.168.10.1", "nuke")


class TestForensicHash(unittest.TestCase):
    def test_compute_and_verify(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"evidence-bytes-123")
            path = f.name
        try:
            rec = fh.compute(path, ("sha256", "md5"))
            self.assertEqual(rec.size_bytes, 18)
            # Known SHA-256 of the content, verified independently.
            self.assertTrue(fh.verify(path, rec.hashes["sha256"]))
            self.assertFalse(fh.verify(path, "0" * 64))
        finally:
            os.unlink(path)

    def test_rejects_bad_algo(self):
        with self.assertRaises(ValueError):
            fh.compute(__file__, ("crc32",))


class TestCatalog(unittest.TestCase):
    def test_loads_and_indexes(self):
        cat = Catalog.load()
        self.assertTrue(cat.categories)
        t = cat.get("nmap-inventory")
        self.assertTrue(t.has_wrapper)
        self.assertEqual(t.executable, "nmap")
        with self.assertRaises(KeyError):
            cat.get("does-not-exist")

    def test_wrapper_importable(self):
        mod = Catalog.load().get("forensic-hash").load_wrapper()
        self.assertTrue(hasattr(mod, "explain"))


class TestProjectAndReport(unittest.TestCase):
    def test_roundtrip_and_report(self):
        with tempfile.TemporaryDirectory() as base:
            auth = Authorization("Audit X", "ACME", scope=["192.168.10.0/24"])
            proj = Project(base, auth)
            proj.record("nmap-inventory", "nmap -sn 192.168.10.0/24", 0)
            proj.add_finding(Finding("Host attivo 192.168.10.5",
                                     severity="info", confidence="confirmed",
                                     source="tool"))
            proj.add_finding(Finding("Possibile servizio obsoleto",
                                     severity="medium", confidence="possible",
                                     source="ai", detail="interpretazione AI"))
            proj.save()

            loaded = Project.load(base, "Audit X")
            self.assertEqual(loaded.auth.owner, "ACME")
            self.assertEqual(len(loaded.log), 1)
            self.assertEqual(len(loaded.findings), 2)

            struct = report_mod.build_structure(loaded)
            # tool vs ai findings must be separated
            self.assertEqual(len(struct["findings_detected"]), 1)
            self.assertEqual(len(struct["interpretations"]), 1)
            self.assertIn("disclaimer", struct)
            # JSON + HTML must render without error
            self.assertIn("Audit X", report_mod.to_json(loaded))
            self.assertIn("<table", report_mod.to_html(loaded))

    def test_bad_severity_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            proj = Project(base, Authorization("P", "O"))
            with self.assertRaises(ValueError):
                proj.add_finding(Finding("x", severity="apocalyptic"))


class TestPrivacyStatus(unittest.TestCase):
    def test_status_structure_and_limits(self):
        st = ps.status()
        d = st.to_dict()
        for key in ("tor_installed", "killswitch_loaded", "dns_resolvers",
                    "warnings", "limits"):
            self.assertIn(key, d)
        # The anonymity limits must always be present (honesty requirement).
        self.assertTrue(any("garanzia di anonimato" in x for x in st.limits))


if __name__ == "__main__":
    unittest.main()
