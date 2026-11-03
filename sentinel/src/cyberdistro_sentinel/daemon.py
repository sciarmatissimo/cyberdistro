"""sentinel-core: follow engine logs, correlate, persist, publish status.

Runs as the unprivileged ``sentinel`` user. Reads:
  /var/log/suricata/eve.json, /var/log/zeek/current/*.log (JSON),
  /var/lib/sentinel/sensor.jsonl
Writes:
  /var/lib/sentinel/sentinel.db  (incidents, devices, actions)
  /run/sentinel/status.json      (colour + counters for the GUI)

``--replay`` processes complete files once (used by tests and to analyse a
capture after the fact) and exits.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .config import Paths, Thresholds
from .events import from_sensor, from_suricata, from_zeek, load_offline
from .rules import Correlator
from .status import Health, decide
from .store import Store

ZEEK_LOGS = ("conn", "dns", "ssh", "notice")


class Tail:
    """Follow a JSON-lines file across truncation and rotation."""

    def __init__(self, path: Path):
        self.path, self.ino, self.pos, self.buf = Path(path), None, 0, ""

    def lines(self):
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []
        if st.st_ino != self.ino or st.st_size < self.pos:
            self.ino, self.pos, self.buf = st.st_ino, 0, ""
        if st.st_size == self.pos:
            return []
        with open(self.path, encoding="utf-8", errors="replace") as fh:
            fh.seek(self.pos)
            data = fh.read(4 * 1024 * 1024)
            self.pos = fh.tell()
        data = self.buf + data
        parts = data.split("\n")
        self.buf = parts.pop()
        out = []
        for p in parts:
            p = p.strip()
            if p and not p.startswith("#"):
                try:
                    out.append(json.loads(p))
                except json.JSONDecodeError:
                    pass
        return out


def proc_running(name: str) -> bool:
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open(f"/proc/{pid}/comm") as fh:
                    if fh.read().strip().startswith(name):
                        return True
            except OSError:
                continue
    return False


def has_default_route() -> bool:
    try:
        with open("/proc/net/route") as fh:
            return any(l.split()[1] == "00000000" for l in fh.readlines()[1:])
    except OSError:
        return False


def write_status(paths: Paths, status: dict, devices: int) -> None:
    paths.run_dir.mkdir(parents=True, exist_ok=True)
    tmp = paths.status_file.with_suffix(".tmp")
    tmp.write_text(json.dumps({**status, "devices": devices}))
    os.replace(tmp, paths.status_file)


def flush(corr: Correlator, store: Store) -> None:
    for inc in corr.pop_changed():
        store.upsert_incident(inc)
    for k, d in corr.devices.items():
        store.upsert_device(k, d)
    store.set_meta("gateway", corr.gateway)
    store.set_meta("self_ip", corr.self_ip)
    store.commit()


def replay(paths: Paths, store: Store, th: Thresholds) -> Correlator:
    corr = Correlator(th)
    corr.run(load_offline(paths.suricata_eve, paths.zeek_dir, paths.sensor_log))
    flush(corr, store)
    return corr


def run(paths: Paths, th: Thresholds, interval: float = 2.0) -> None:
    store = Store(paths.db)
    corr = Correlator(th)
    tails = {"suricata": Tail(paths.suricata_eve), "sensor": Tail(paths.sensor_log)}
    for n in ZEEK_LOGS:
        tails[f"zeek:{n}"] = Tail(paths.zeek_dir / f"{n}.log")
    while True:
        batch = []
        for name, t in tails.items():
            for rec in t.lines():
                if name == "suricata":
                    ev = from_suricata(rec)
                elif name == "sensor":
                    ev = from_sensor(rec)
                else:
                    ev = from_zeek(name.split(":")[1], rec)
                if ev:
                    batch.append(ev)
        batch.sort(key=lambda e: e.ts)
        for ev in batch:
            corr.process(ev)
        flush(corr, store)
        health = Health(suricata=proc_running("Suricata") or proc_running("suricata"),
                        zeek=proc_running("zeek"), sensor=proc_running("sentinel-sensor"),
                        network=has_default_route())
        st = decide(store.incidents(time.time() - th.status_window), health, time.time(), th.status_window)
        write_status(paths, st, len(corr.devices))
        time.sleep(interval)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberDistro Sentinel correlation daemon")
    ap.add_argument("--replay", action="store_true", help="process complete log files once and exit")
    ap.add_argument("--json", action="store_true", help="with --replay: print incidents as JSON")
    args = ap.parse_args(argv)
    paths, th = Paths(), Thresholds()
    if args.replay:
        store = Store(paths.db)
        corr = replay(paths, store, th)
        incs = store.incidents()
        if args.json:
            print(json.dumps({"incidents": incs, "devices": store.devices()}, indent=1, default=str))
        else:
            for i in incs:
                print(f"[{i['severity']:5}] [{i['level']:10}] {i['rule']:20} {i['src']} -> {i['dst']}  {i['facts']}")
            print(f"{len(incs)} incidenti, {len(corr.devices)} dispositivi")
        return 0
    run(paths, th)
    return 0


if __name__ == "__main__":
    sys.exit(main())
