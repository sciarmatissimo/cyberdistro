"""On-demand launcher for a local LLM server (llama.cpp).

Goal: make the assistant genuinely conversational — like the Sentinel edition —
without requiring the user to start anything by hand, and without a cloud
service. If a GGUF model and the ``llama-server`` runtime are present on the
machine (bundled at build time under ``/opt/cyberdistro`` or dropped in by the
user), this module starts the server on demand, on a localhost-only port, with
a RAM safety gate, and exposes its OpenAI-compatible URL. If nothing is present
it stays completely inert (no process, no error) and the assistant degrades to
its offline knowledge base.

Design notes:
  * **Local only.** The server binds to 127.0.0.1 and has no web UI.
  * **Lazy & safe.** Nothing happens on import. ``ensure_running`` is the only
    entry point that may spawn a process, and only when a model + runtime exist
    and enough RAM is free. Any failure returns ``None`` instead of raising.
  * **Testable.** ``mem_available_mb``, the spawn and the health check are
    injectable, so unit tests never touch ``/opt`` or start a real process.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

# Shared layout with the Sentinel edition, so a build may reuse the same
# artifacts. Overridable via environment for power users / drop-in models.
MODEL_DIR = Path(os.environ.get("CYBERDISTRO_AI_MODEL_DIR", "/opt/cyberdistro/models"))
RUNTIME = Path(os.environ.get("CYBERDISTRO_AI_LLAMA", "/opt/cyberdistro/llama/llama-server"))

# A small instruct model (~0.5–1 B, 4-bit) runs comfortably in well under a
# gigabyte of RAM; keep a conservative floor so we never push a live USB session
# into swap. Overridable for larger bundled models.
MIN_FREE_MB = int(os.environ.get("CYBERDISTRO_AI_MIN_FREE_MB", "900"))
CTX_TOKENS = int(os.environ.get("CYBERDISTRO_AI_CTX", "4096"))
IDLE_SECONDS = int(os.environ.get("CYBERDISTRO_AI_IDLE", "600"))
START_TIMEOUT = float(os.environ.get("CYBERDISTRO_AI_START_TIMEOUT", "180"))


# ------------------------------------------------------------- discovery
def model_path() -> Path | None:
    """The GGUF model to serve, or None. Explicit env wins; else the first
    ``*.gguf`` found in the model directory (sorted for determinism)."""
    env = os.environ.get("CYBERDISTRO_AI_MODEL_PATH")
    if env:
        p = Path(env)
        return p if p.is_file() else None
    try:
        files = sorted(MODEL_DIR.glob("*.gguf"))
    except OSError:
        return None
    return files[0] if files else None


def runtime_path() -> Path | None:
    """The llama-server executable, or None."""
    return RUNTIME if os.access(RUNTIME, os.X_OK) else None


def mem_available_mb() -> int:
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    return 0


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def availability(mem=mem_available_mb) -> tuple[bool, str]:
    """(ok, reason). ``ok`` means a local model *could* be started now."""
    if model_path() is None:
        return False, "no-model"
    if runtime_path() is None:
        return False, "no-runtime"
    free = mem()
    if free and free < MIN_FREE_MB:
        return False, f"low-ram:{free}<{MIN_FREE_MB}"
    return True, "ready"


# --------------------------------------------------------------- server
class LocalServer:
    """Manages a single on-demand llama-server process."""

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self.last_use = 0.0
        self._lock = threading.Lock()

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def url(self) -> str | None:
        if self.running() and self.port:
            return f"http://127.0.0.1:{self.port}/v1/chat/completions"
        return None

    def _spawn(self, model: Path, runtime: Path, port: int) -> subprocess.Popen:
        threads = str(max(1, (os.cpu_count() or 2)))
        return subprocess.Popen(
            [str(runtime), "-m", str(model), "-t", threads, "-c", str(CTX_TOKENS),
             "--host", "127.0.0.1", "--port", str(port), "--no-webui"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "LD_LIBRARY_PATH": str(runtime.parent)})

    def _healthy(self, port: int, timeout: float = 2.0) -> bool:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health",
                                        timeout=timeout) as r:  # noqa: S310 (localhost)
                return r.status < 500
        except OSError:
            return False

    def start(self, *, spawn=None, healthy=None, mem=mem_available_mb,
              timeout: float = START_TIMEOUT) -> str | None:
        """Start the server if needed; return its URL, or None if it can't run.
        Never raises. ``spawn``/``healthy`` are injectable for tests."""
        with self._lock:
            if self.running():
                self.last_use = time.time()
                return self.url()
            model, runtime = model_path(), runtime_path()
            ok, _ = availability(mem=mem)
            if not ok or model is None or runtime is None:
                return None
            port = _free_port()
            spawn = spawn or self._spawn
            healthy = healthy or self._healthy
            try:
                self.proc = spawn(model, runtime, port)
            except (OSError, ValueError):
                self.proc = None
                return None
            self.port = port
            t0 = time.time()
            while time.time() - t0 < timeout:
                if self.proc.poll() is not None:        # exited during startup
                    self.proc = None
                    self.port = None
                    return None
                if healthy(port):
                    self.last_use = time.time()
                    return self.url()
                time.sleep(1.0)
            self._stop_locked()                         # timed out starting up
            return None

    def _stop_locked(self) -> None:
        """Terminate the process; caller must already hold ``self._lock``."""
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        self.port = None

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def stop_if_idle(self) -> None:
        if self.running() and time.time() - self.last_use > IDLE_SECONDS:
            self.stop()


_SERVER = LocalServer()


def server() -> LocalServer:
    return _SERVER


def ensure_running(**kw) -> str | None:
    """Convenience: start (or reuse) the shared server, return its URL or None."""
    return _SERVER.start(**kw)
