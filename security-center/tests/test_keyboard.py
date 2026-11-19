"""Unit tests for the keyboard-layout selector (independent of UI language)."""

import subprocess
import unittest

from cyberdistro_sc.tools import keyboard as kb


class TestKeyboard(unittest.TestCase):
    def test_layouts_unique_and_labeled(self):
        codes = [c for c, _ in kb.layouts()]
        self.assertEqual(len(codes), len(set(codes)), "duplicate layout codes")
        self.assertIn("it", codes)
        self.assertIn("us", codes)
        self.assertIn("de", codes)
        self.assertEqual(kb.label_for("it"), "Italiano")
        self.assertEqual(kb.label_for("zz"), "zz")

    def test_parse_query(self):
        out = "rules:      evdev\nmodel:      pc105\nlayout:     it,us\nvariant:\n"
        self.assertEqual(kb.parse_query(out), "it")
        self.assertEqual(kb.parse_query("layout: us"), "us")
        self.assertEqual(kb.parse_query("no layout here"), "")

    def test_validation(self):
        self.assertTrue(kb.is_valid("it"))
        self.assertTrue(kb.is_valid("latam"))
        self.assertFalse(kb.is_valid("it; rm -rf"))
        self.assertFalse(kb.is_valid(""))

    def test_plan_set_is_argv(self):
        self.assertEqual(kb.plan_set("de"), ["setxkbmap", "de"])

    def test_apply_rejects_bad_code(self):
        with self.assertRaises(ValueError):
            kb.apply_layout("../evil", run=lambda a, timeout=0: None, persist=False)

    def test_apply_runs_setxkbmap(self):
        calls = []

        def fake(argv, timeout=10.0):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        kb.apply_layout("fr", run=fake, persist=False)
        self.assertEqual(calls, [["setxkbmap", "fr"]])

    def test_current_layout_prefers_query(self):
        def fake(argv, timeout=10.0):
            return subprocess.CompletedProcess(argv, 0, "layout: es,us\n", "")
        self.assertEqual(kb.current_layout(run=fake), "es")


if __name__ == "__main__":
    unittest.main()
