"""Runtime capability detection.

The Security Center must tell the truth about what is actually available on THIS
machine right now: which tools are installed, and which hardware features exist
(e.g. does a Wi-Fi adapter support monitor mode). It must never promise a
capability the hardware/software does not provide.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class ToolStatus:
    tool_id: str
    executable: str
    installed: bool
    version: str = ""
    path: str = ""

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "executable": self.executable,
            "installed": self.installed,
            "version": self.version,
            "path": self.path,
        }


def _probe_version(executable: str) -> str:
    """Best-effort version string; never raises."""
    for flag in ("--version", "-V", "-version", "version"):
        try:
            p = subprocess.run([executable, flag], capture_output=True,
                               text=True, timeout=5, check=False)
            text = (p.stdout or "") + (p.stderr or "")
            m = re.search(r"\d+\.\d+(?:\.\d+)?", text)
            if m:
                return m.group(0)
            first = text.strip().splitlines()[0] if text.strip() else ""
            if first:
                return first[:60]
        except Exception:
            continue
    return ""


def detect_tool(tool_id: str, executable: str) -> ToolStatus:
    path = shutil.which(executable)
    if not path:
        return ToolStatus(tool_id, executable, installed=False)
    return ToolStatus(tool_id, executable, installed=True,
                      version=_probe_version(executable), path=path)


def wifi_interfaces() -> list[str]:
    """List wireless interfaces (empty if none / not detectable)."""
    base = "/sys/class/net"
    out = []
    if not os.path.isdir(base):
        return out
    for iface in os.listdir(base):
        if os.path.isdir(os.path.join(base, iface, "wireless")) or \
           os.path.exists(os.path.join(base, iface, "phy80211")):
            out.append(iface)
    return out


def wifi_supports_monitor(iface: str) -> bool | None:
    """Whether ``iface`` advertises monitor mode.

    Returns True/False when it can be determined via `iw`, or None if it cannot
    be determined (iw missing / no phy info). None means "unknown" — the UI must
    say "unknown", never assume support.
    """
    if shutil.which("iw") is None:
        return None
    try:
        phy = None
        phyfile = f"/sys/class/net/{iface}/phy80211/name"
        if os.path.exists(phyfile):
            with open(phyfile) as fh:
                phy = fh.read().strip()
        if not phy:
            return None
        p = subprocess.run(["iw", "phy", phy, "info"], capture_output=True,
                           text=True, timeout=5, check=False)
        txt = p.stdout
        if "Supported interface modes" not in txt:
            return None
        return bool(re.search(r"^\s*\*\s*monitor\s*$", txt, re.MULTILINE))
    except Exception:
        return None


def system_report() -> dict:
    """A truthful snapshot used by `cyberdistro-sc doctor` and the dashboard."""
    report: dict = {"wifi": {}, "notes": []}
    try:
        import psutil  # optional
        vm = psutil.virtual_memory()
        report["memory_total_mb"] = vm.total // (1024 * 1024)
        report["memory_available_mb"] = vm.available // (1024 * 1024)
        report["cpu_logical"] = psutil.cpu_count()
    except Exception:
        report["notes"].append("psutil not available; memory/cpu omitted")

    for iface in wifi_interfaces():
        mon = wifi_supports_monitor(iface)
        report["wifi"][iface] = (
            "monitor-capable" if mon is True else
            "no-monitor" if mon is False else
            "unknown (external adapter may be required)"
        )
    if not report["wifi"]:
        report["notes"].append("no wireless interface detected")

    # Tor presence (does not test connectivity here; privacy_status does that)
    report["tor_installed"] = shutil.which("tor") is not None
    report["tor_browser_present"] = os.path.isdir("/opt/tor-browser")
    return report
