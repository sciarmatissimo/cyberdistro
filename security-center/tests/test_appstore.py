"""Unit tests for the on-demand application catalog (appstore)."""

import glob
import os
import re
import unittest

from cyberdistro_sc.tools.appstore import AppStore, App, INSTALL_HELPER

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class TestAppStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = AppStore.load()

    def test_two_sections_present(self):
        ids = [s.id for s in self.store.sections]
        self.assertEqual(ids, ["forensics", "reversing"])
        for s in self.store.sections:
            self.assertTrue(s.apps, s.id)
            self.assertTrue(s.title_it and s.intro_it)

    def test_every_app_is_valid_and_documented(self):
        for a in self.store.all_apps():
            a.validate()  # raises on bad source/launch
            self.assertTrue(a.name and a.desc_it and a.use_it, a.id)
            self.assertIn(a.source, ("debian", "kali", "pip"))
            self.assertIn(a.launch, ("gui", "gui-root", "web", "terminal"))

    def test_gui_apps_sorted_first(self):
        for s in self.store.sections:
            guis = [a.gui for a in s.apps]
            self.assertEqual(guis, sorted(guis, reverse=True), s.id)
        # each section leads with at least one graphical tool
        for s in self.store.sections:
            self.assertTrue(s.apps[0].gui, f"{s.id} should start with a GUI app")

    def test_install_argv_is_list_and_uses_helper(self):
        for a in self.store.all_apps():
            argv = a.install_argv()
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[0], "pkexec")
            self.assertEqual(argv[1], INSTALL_HELPER)
            self.assertIn(argv[2], ("--apt", "--kali", "--pip"))
            # packages are passed as separate args (no shell string)
            self.assertEqual(argv[3:], a.packages)
            # unprivileged form drops pkexec
            self.assertEqual(a.install_argv(privileged=False)[0], INSTALL_HELPER)

    def test_launch_argv_never_a_shell_string(self):
        for a in self.store.all_apps():
            argv = a.launch_argv()
            self.assertIsInstance(argv, list)
            self.assertTrue(all(isinstance(x, str) for x in argv))
            if a.launch == "gui":
                self.assertEqual(argv, [a.binary])
            if a.launch == "gui-root":
                self.assertEqual(argv[0], "pkexec")

    def test_source_matches_known_availability(self):
        # Tools not packaged in Debian trixie must come from kali or pip.
        by_id = {a.id: a for a in self.store.all_apps()}
        self.assertEqual(by_id["ghidra"].source, "kali")
        self.assertEqual(by_id["radare2"].source, "kali")
        self.assertEqual(by_id["volatility3"].source, "pip")
        # gdb must come from Debian (Kali's build needs a newer libc than trixie)
        self.assertEqual(by_id["gdb"].source, "debian")

    def test_apps_are_not_prebaked_in_package_lists(self):
        """The whole point: on-demand apps must NOT be in the baked image lists."""
        baked = set()
        for f in glob.glob(os.path.join(REPO, "build/config/package-lists/*.list.chroot")):
            for line in open(f, encoding="utf-8"):
                line = line.split("#")[0].strip()
                if line:
                    baked.add(line)
        offenders = []
        for a in self.store.all_apps():
            if a.source == "pip":
                continue
            for pkg in a.packages:
                if pkg in baked:
                    offenders.append((a.id, pkg))
        self.assertEqual(offenders, [], f"on-demand packages still pre-baked: {offenders}")


if __name__ == "__main__":
    unittest.main()
