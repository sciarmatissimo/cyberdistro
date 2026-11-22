"""Unit tests for the on-demand local-model launcher (no real process)."""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from cyberdistro_sc.tools import localmodel as lm


class _FakeProc:
    """Minimal subprocess.Popen stand-in."""
    def __init__(self, alive=True):
        self._alive = alive
        self.terminated = False

    def poll(self):
        return None if self._alive else 1

    def terminate(self):
        self.terminated = True
        self._alive = False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self._alive = False


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self._saved = (lm.MODEL_DIR, lm.RUNTIME)

    def tearDown(self):
        lm.MODEL_DIR, lm.RUNTIME = self._saved
        for k in ("CYBERDISTRO_AI_MODEL_PATH",):
            os.environ.pop(k, None)

    def test_model_path_none_when_absent(self):
        lm.MODEL_DIR = Path("/nonexistent/cyberdistro/models")
        self.assertIsNone(lm.model_path())

    def test_model_path_finds_gguf(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "small.gguf").write_bytes(b"x")
            lm.MODEL_DIR = Path(d)
            self.assertEqual(lm.model_path().name, "small.gguf")

    def test_model_path_env_override(self):
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(b"x")
            name = f.name
        try:
            os.environ["CYBERDISTRO_AI_MODEL_PATH"] = name
            self.assertEqual(str(lm.model_path()), name)
        finally:
            os.unlink(name)

    def test_availability_no_model(self):
        lm.MODEL_DIR = Path("/nonexistent/models")
        ok, why = lm.availability()
        self.assertFalse(ok)
        self.assertEqual(why, "no-model")

    def test_availability_low_ram(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "m.gguf").write_bytes(b"x")
            rt = Path(d) / "llama-server"
            rt.write_text("#!/bin/sh\n")
            rt.chmod(rt.stat().st_mode | stat.S_IEXEC)
            lm.MODEL_DIR, lm.RUNTIME = Path(d), rt
            ok, why = lm.availability(mem=lambda: 100)
            self.assertFalse(ok)
            self.assertTrue(why.startswith("low-ram"))
            ok2, why2 = lm.availability(mem=lambda: 999999)
            self.assertTrue(ok2)
            self.assertEqual(why2, "ready")


class TestServerStart(unittest.TestCase):
    def setUp(self):
        self._saved = (lm.MODEL_DIR, lm.RUNTIME)
        self.d = tempfile.TemporaryDirectory()
        p = Path(self.d.name)
        (p / "m.gguf").write_bytes(b"x")
        rt = p / "llama-server"
        rt.write_text("#!/bin/sh\n")
        rt.chmod(rt.stat().st_mode | stat.S_IEXEC)
        lm.MODEL_DIR, lm.RUNTIME = p, rt
        self.srv = lm.LocalServer()

    def tearDown(self):
        lm.MODEL_DIR, lm.RUNTIME = self._saved
        self.d.cleanup()

    def test_start_returns_url_when_healthy(self):
        url = self.srv.start(spawn=lambda m, r, port: _FakeProc(True),
                             healthy=lambda port, timeout=2.0: True,
                             mem=lambda: 999999)
        self.assertIsNotNone(url)
        self.assertRegex(url, r"^http://127\.0\.0\.1:\d+/v1/chat/completions$")
        self.assertTrue(self.srv.running())
        self.srv.stop()
        self.assertFalse(self.srv.running())

    def test_start_none_when_process_exits(self):
        url = self.srv.start(spawn=lambda m, r, port: _FakeProc(False),
                             healthy=lambda port, timeout=2.0: False,
                             mem=lambda: 999999)
        self.assertIsNone(url)

    def test_start_none_when_never_healthy(self):
        url = self.srv.start(spawn=lambda m, r, port: _FakeProc(True),
                             healthy=lambda port, timeout=2.0: False,
                             mem=lambda: 999999, timeout=0.2)
        self.assertIsNone(url)

    def test_start_none_when_no_ram(self):
        url = self.srv.start(spawn=lambda m, r, port: _FakeProc(True),
                             healthy=lambda port, timeout=2.0: True,
                             mem=lambda: 1)
        self.assertIsNone(url)


if __name__ == "__main__":
    unittest.main()
