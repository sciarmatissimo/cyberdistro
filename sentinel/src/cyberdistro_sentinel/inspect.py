"""Deep network inspection (2b): read, for a bounded time window, what every
device on the network is doing — who it talks to, how much, and which sites it
looks up — and present it per device.

The capture itself is done by the privileged ``sentinel-inspect`` helper, which
briefly routes the LAN's traffic through this PC (forwarding it, so nothing is
cut off), for a number of minutes the user chooses, with an automatic stop and a
clear warning. This module is the read-only half: it summarises Zeek's logs over
the window. It parses logs only; it never touches the network.

Only connection metadata is shown — addresses, ports, byte counts, and the
names looked up via DNS. The contents of encrypted traffic are never visible.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections import defaultdict
from pathlib import Path

from .events import read_jsonl

STATE_FILE = "inspect.json"            # under run_dir, written by sentinel-inspect
MAX_MINUTES = 10
DEFAULT_MINUTES = 3


def _priv(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def per_device(conn_recs, dns_recs, self_ips: set[str], gateway: str | None,
               t0: float, t1: float) -> list[dict]:
    """Group connection metadata by the local device involved (not this PC, not
    the router). Returns one summary per device, busiest first."""
    dev = defaultdict(lambda: {"conns": 0, "bytes": 0, "peers": set(), "ext_peers": set(),
                               "ports": defaultdict(int), "names": set()})
    skip = set(self_ips) | ({gateway} if gateway else set())
    for rec in conn_recs:
        ts = rec.get("ts", 0)
        if not (t0 <= ts <= t1):
            continue
        o, r = rec.get("id.orig_h"), rec.get("id.resp_h")
        if not o or not r:
            continue
        local = o if (_priv(o) and o not in skip) else r if (_priv(r) and r not in skip) else None
        if not local:
            continue
        peer = r if local == o else o
        d = dev[local]
        d["conns"] += 1
        d["bytes"] += (rec.get("orig_bytes") or 0) + (rec.get("resp_bytes") or 0)
        d["peers"].add(peer)
        if not _priv(peer):
            d["ext_peers"].add(peer)
        if local == o and rec.get("id.resp_p") is not None:
            d["ports"][int(rec["id.resp_p"])] += 1
    for rec in dns_recs:
        ts = rec.get("ts", 0)
        o = rec.get("id.orig_h")
        if o and t0 <= ts <= t1 and o in dev and rec.get("query"):
            dev[o]["names"].add(str(rec["query"])[:80])
    out = []
    for ip, d in dev.items():
        out.append({"ip": ip, "conns": d["conns"], "bytes": d["bytes"],
                    "peers": len(d["peers"]), "ext_peers": len(d["ext_peers"]),
                    "top_ports": [p for p, _ in sorted(d["ports"].items(), key=lambda kv: -kv[1])[:6]],
                    "dns_names": sorted(d["names"])[:12]})
    out.sort(key=lambda x: -x["bytes"])
    return out


def device_line(d: dict) -> str:
    kb = d["bytes"] // 1024
    vol = f"{kb} KB" if kb < 1024 else f"{kb / 1024:.1f} MB"
    t = (f"{d['ip']}: {d['conns']} connessioni con {d['peers']} indirizzi"
         + (f" ({d['ext_peers']} su internet)" if d["ext_peers"] else "") + f", {vol}.")
    if d["top_ports"]:
        t += " Porte: " + ", ".join(map(str, d["top_ports"])) + "."
    return t


def read_state(run_dir: Path) -> dict:
    try:
        return json.loads((run_dir / STATE_FILE).read_text())
    except (OSError, ValueError):
        return {"state": "idle"}


def summarize(zeek_dir: Path, t0: float, t1: float, self_ips: set[str], gateway: str | None) -> list[dict]:
    def recs(name):
        try:
            return list(read_jsonl(zeek_dir / name))
        except OSError:
            return []
    return per_device(recs("conn.log"), recs("dns.log"), self_ips, gateway, t0, t1)


def now() -> float:
    return time.time()
