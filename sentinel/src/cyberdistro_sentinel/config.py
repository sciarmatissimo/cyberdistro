"""Runtime paths and thresholds. Everything can be overridden by environment
variables so that tests and offline replays can point at fixture files."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _p(env: str, default: str) -> Path:
    return Path(os.environ.get(env, default))


@dataclass
class Paths:
    state_dir: Path = field(default_factory=lambda: _p("SENTINEL_STATE", "/var/lib/sentinel"))
    run_dir: Path = field(default_factory=lambda: _p("SENTINEL_RUN", "/run/sentinel"))
    suricata_eve: Path = field(default_factory=lambda: _p("SENTINEL_EVE", "/var/log/suricata/eve.json"))
    zeek_dir: Path = field(default_factory=lambda: _p("SENTINEL_ZEEK", "/var/log/zeek/current"))
    sensor_log: Path = field(default_factory=lambda: _p("SENTINEL_SENSOR_LOG", "/var/lib/sentinel/sensor.jsonl"))
    model: Path = field(default_factory=lambda: _p(
        "SENTINEL_MODEL", "/opt/cyberdistro/models/Qwen3.5-2B-Q3_K_M.gguf"))
    llama_server: Path = field(default_factory=lambda: _p(
        "SENTINEL_LLAMA", "/opt/cyberdistro/llama/llama-server"))

    @property
    def db(self) -> Path:
        return self.state_dir / "sentinel.db"

    @property
    def status_file(self) -> Path:
        return self.run_dir / "status.json"


@dataclass
class Thresholds:
    # Port scan: distinct destination ports probed by one source on one target.
    scan_ports: int = 25
    scan_window: float = 60.0
    # Horizontal sweep: distinct targets on one port.
    sweep_hosts: int = 20
    # Brute force: connections from one source to one login service.
    brute_conns: int = 10
    brute_window: float = 120.0
    brute_ports: tuple = (21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5900)
    # DNS
    nxdomain_count: int = 25
    nxdomain_window: float = 300.0
    tunnel_label_len: int = 40
    tunnel_count: int = 20
    tunnel_window: float = 300.0
    # Beaconing: periodic connections to the same external endpoint.
    beacon_min_conns: int = 6
    beacon_max_cv: float = 0.15
    beacon_min_interval: float = 10.0
    # Exfiltration: bytes sent from one internal host to one external host.
    exfil_bytes: int = 200 * 1024 * 1024
    exfil_window: float = 600.0
    # Lateral movement: one internal host reaching many internal hosts on admin ports.
    lateral_hosts: int = 5
    lateral_window: float = 600.0
    lateral_ports: tuple = (22, 135, 139, 445, 3389, 5985, 5986)
    # Devices
    learning_period: float = 120.0
    # Status
    status_window: float = 3600.0
    engine_silence: float = 90.0
