"""Normalisation of engine records into one event shape.

Every record that enters the correlation layer becomes an ``Event``:
    ts       epoch seconds (float), taken from the record itself
    engine   "suricata" | "zeek" | "sensor"
    kind     "alert" | "conn" | "dns" | "ssh" | "http" | "arp" | "device" | ...
    ref      stable identifier of the source record (evidence pointer)
    src/dst  addresses; sport/dport ports when known
    data     the engine-specific fields we keep (already size-limited)

Strings that come from the network (DNS names, user agents, hostnames) are
untrusted: they are kept for the evidence view but truncated, and they are
never passed to the language model (see ``assistant.facts``).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Iterator

MAX_STR = 200


def clip(v: Any, n: int = MAX_STR) -> Any:
    if isinstance(v, str) and len(v) > n:
        return v[:n] + "…"
    return v


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_link_local or a.is_loopback


@dataclass
class Event:
    ts: float
    engine: str
    kind: str
    ref: str
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ts": self.ts, "engine": self.engine, "kind": self.kind, "ref": self.ref,
                "src": self.src, "dst": self.dst, "sport": self.sport, "dport": self.dport,
                "data": self.data}


def _ts_iso(s: str) -> float:
    # Suricata: 2023-11-14T22:13:20.002000+0000
    s = s.replace("Z", "+0000")
    if len(s) > 5 and (s[-5] in "+-") and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    return datetime.fromisoformat(s).timestamp()


def from_suricata(rec: dict) -> Event | None:
    et = rec.get("event_type")
    try:
        ts = _ts_iso(rec["timestamp"])
    except (KeyError, ValueError):
        return None
    base = dict(ts=ts, engine="suricata", src=rec.get("src_ip"), dst=rec.get("dest_ip"),
                sport=rec.get("src_port"), dport=rec.get("dest_port"))
    if et == "alert":
        a = rec.get("alert", {})
        return Event(kind="alert",
                     ref=f"suricata:{rec.get('flow_id', '')}:{a.get('signature_id', '')}:{ts:.6f}",
                     data={"signature": clip(a.get("signature", "")),
                           "signature_id": a.get("signature_id"),
                           "severity": a.get("severity", 3),
                           "category": clip(a.get("category", "")),
                           "proto": rec.get("proto")}, **base)
    if et == "stats":
        return Event(kind="stats", ref=f"suricata:stats:{ts:.0f}",
                     data={"packets": rec.get("stats", {}).get("capture", {}).get("kernel_packets", 0)},
                     ts=ts, engine="suricata")
    return None


def from_zeek(logname: str, rec: dict) -> Event | None:
    try:
        ts = float(rec["ts"])
    except (KeyError, TypeError, ValueError):
        return None
    uid = rec.get("uid", "")
    base = dict(ts=ts, engine="zeek", src=rec.get("id.orig_h"), dst=rec.get("id.resp_h"),
                sport=rec.get("id.orig_p"), dport=rec.get("id.resp_p"))
    if logname == "conn":
        return Event(kind="conn", ref=f"zeek:conn:{uid}", data={
            "proto": rec.get("proto"), "service": rec.get("service"),
            "state": rec.get("conn_state"), "orig_bytes": rec.get("orig_bytes") or 0,
            "resp_bytes": rec.get("resp_bytes") or 0, "duration": rec.get("duration") or 0.0,
            "local_orig": rec.get("local_orig")}, **base)
    if logname == "dns":
        return Event(kind="dns", ref=f"zeek:dns:{uid}:{rec.get('trans_id', '')}", data={
            "query": clip(rec.get("query") or ""), "qtype": rec.get("qtype_name"),
            "rcode": rec.get("rcode_name")}, **base)
    if logname == "ssh":
        return Event(kind="ssh", ref=f"zeek:ssh:{uid}", data={
            "auth_success": rec.get("auth_success"), "auth_attempts": rec.get("auth_attempts"),
            "client": clip(rec.get("client") or "")}, **base)
    if logname == "notice":
        return Event(kind="notice", ref=f"zeek:notice:{uid or ts}", data={
            "note": rec.get("note"), "msg": clip(rec.get("msg") or "")}, **base)
    return None


def from_sensor(rec: dict) -> Event | None:
    try:
        return Event(ts=float(rec["ts"]), engine="sensor", kind=rec["kind"],
                     ref=f"sensor:{rec.get('seq', rec['ts'])}", src=rec.get("ip"),
                     data={k: clip(v) for k, v in rec.items() if k not in ("ts", "kind", "seq")})
    except (KeyError, TypeError, ValueError):
        return None


def read_jsonl(path) -> Iterator[dict]:
    import gzip
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_offline(eve=None, zeek_dir=None, sensor=None) -> list[Event]:
    """Load complete log files (replay / tests) and return events sorted by time."""
    from pathlib import Path
    out: list[Event] = []
    if eve and Path(eve).exists():
        out += [e for e in map(from_suricata, read_jsonl(eve)) if e]
    if zeek_dir:
        for name in ("conn", "dns", "ssh", "notice"):
            for p in (Path(zeek_dir) / f"{name}.log", Path(zeek_dir) / f"{name}.log.gz"):
                if p.exists():
                    out += [e for e in (from_zeek(name, r) for r in read_jsonl(p)) if e]
    if sensor and Path(sensor).exists():
        out += [e for e in map(from_sensor, read_jsonl(sensor)) if e]
    out.sort(key=lambda e: e.ts)
    return out


def sort_events(evs: Iterable[Event]) -> list[Event]:
    return sorted(evs, key=lambda e: e.ts)
