"""Active discovery (census): enumerate every device on the local network, not
just the ones that talk to this PC.

The only active step is an **ARP sweep of this PC's own subnet**: one ARP request
per address. ARP is link-local, never leaves the LAN, and every operating system
does it routinely — it is the mildest possible active probe. It runs only when the
user has declared "this is my network" and turned the census on; Sentinel stays
passive by default.

The replies arrive through the sensor's existing listening socket and are parsed
by ``sensor.parse_frame`` like any other ARP, so a swept host shows up as a normal
device. This module only builds the request frames and lists the addresses; it
sends nothing by itself (the sensor owns the raw socket).

It also decides, from Zeek's own connection log, whether this PC is on a network
*tap* (hub or switch mirror port) — i.e. whether it already sees traffic between
other devices without any redirection.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from .events import read_jsonl

ETH_BROADCAST = b"\xff\xff\xff\xff\xff\xff"
MAX_SWEEP = 1024                      # never sweep more than a /22, whatever the mask


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def arp_request_frame(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    """A broadcast ARP "who has <target_ip>?" asked by (src_mac, src_ip)."""
    sha = _mac_bytes(src_mac)
    spa = ipaddress.IPv4Address(src_ip).packed
    tpa = ipaddress.IPv4Address(target_ip).packed
    eth = ETH_BROADCAST + sha + b"\x08\x06"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sha + spa + b"\x00" * 6 + tpa
    return eth + arp


def subnet_hosts(ip: str, netmask: str, cap: int = MAX_SWEEP) -> list[str]:
    """Usable host addresses of the subnet ``ip``/``netmask`` belongs to,
    excluding network, broadcast and ``ip`` itself. Capped for safety."""
    try:
        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return []
    if net.num_addresses > cap * 4:          # absurdly large mask: refuse rather than guess
        return []
    me = ipaddress.IPv4Address(ip)
    out = [str(h) for h in net.hosts() if h != me]
    return out[:cap]


def is_tap(conn_log: Path, self_ips: set[str], min_foreign: int = 20,
           max_lines: int = 50000) -> dict:
    """Is this PC on a hub or a mirror port? True when Zeek logged many connections
    where neither endpoint is this PC — traffic we could only see on a tap."""
    foreign = 0
    pairs = set()
    try:
        recs = list(read_jsonl(conn_log))
    except OSError:
        return {"tap": False, "foreign_conns": 0, "foreign_pairs": 0}
    for rec in recs[-max_lines:]:
        o, r = rec.get("id.orig_h"), rec.get("id.resp_h")
        if not o or not r:
            continue
        if o in self_ips or r in self_ips:
            continue
        if _is_global_multicast_or_bcast(r):       # broadcast/multicast is seen without a tap
            continue
        foreign += 1
        pairs.add((o, r))
    return {"tap": foreign >= min_foreign and len(pairs) >= 3,
            "foreign_conns": foreign, "foreign_pairs": len(pairs)}


def _is_global_multicast_or_bcast(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_multicast or a.is_unspecified or str(a).endswith(".255") or str(a) == "255.255.255.255"
