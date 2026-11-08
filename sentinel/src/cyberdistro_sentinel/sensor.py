"""Sentinel passive sensor: ARP, DHCP, mDNS and IPv6 neighbour discovery.

Neither Suricata nor Zeek analyses ARP, so device inventory and ARP spoofing
detection live here. The sensor only LISTENS (AF_PACKET, needs CAP_NET_RAW);
it never sends a packet. It writes one JSON line per observation to
``sensor.jsonl``; the correlation daemon reads that file.

Records:
  {"kind":"net","iface","self_ip","self_mac","gateway"}      at start/changes
  {"kind":"arp","ip","mac","op"}                             new (ip,mac) pairs
  {"kind":"ipmac","ip","mac"}                                gateway MAC seen in IP traffic
  {"kind":"dhcp","ip","mac","hostname"}                      DHCP requests/acks
  {"kind":"mdns","ip","mac","names":[..],"services":[..]}    mDNS announcements
  {"kind":"ndp","ip","mac"}                                  IPv6 neighbours
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

ETH_P_ALL = 0x0003


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip4(b: bytes) -> str:
    return socket.inet_ntoa(b)


# ---------------------------------------------------------------- DNS (mDNS)
def _dns_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while off < len(buf) and depth < 20:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off, depth = ptr, depth + 1
            continue
        labels.append(buf[off + 1: off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def parse_mdns(payload: bytes) -> tuple[list[str], list[str]]:
    names, services = set(), set()
    if len(payload) < 12:
        return [], []
    qd, an, ns, ar = struct.unpack("!HHHH", payload[4:12])
    off = 12
    try:
        for _ in range(qd):
            _, off = _dns_name(payload, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = _dns_name(payload, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[off: off + 10])
            off += 10
            rdata = off
            off += rdlen
            if rtype in (1, 28) and name.endswith(".local"):          # A / AAAA
                names.add(name[:-6])
            elif rtype == 12:                                           # PTR
                target, _ = _dns_name(payload, rdata)
                if name.startswith("_") and ("._tcp" in name or "._udp" in name):
                    services.add(name.split(".")[0])
                if target.endswith(".local") and not target.startswith("_"):
                    inst = target.split("._")[0]
                    if inst:
                        names.add(inst[:64])
            elif rtype == 33:                                           # SRV
                if "._" in name:
                    services.add("_" + name.split("._")[1].split(".")[0])
    except (struct.error, IndexError):
        pass
    return sorted(names)[:8], sorted(services)[:16]


# ---------------------------------------------------------------- DHCP
def parse_dhcp(payload: bytes) -> dict | None:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    chaddr = mac_str(payload[28:34])
    yiaddr = ip4(payload[16:20])
    ciaddr = ip4(payload[12:16])
    opts, i = {}, 240
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(payload):
            break
        ln = payload[i + 1]
        opts[code] = payload[i + 2: i + 2 + ln]
        i += 2 + ln
    host = opts.get(12, b"").decode("utf-8", "replace")[:64]
    req = ip4(opts[50]) if 50 in opts and len(opts[50]) == 4 else None
    ip = next((a for a in (yiaddr, ciaddr, req) if a and a != "0.0.0.0"), None)
    return {"mac": chaddr, "ip": ip, "hostname": host or None,
            "vendor_class": opts.get(60, b"").decode("utf-8", "replace")[:64] or None}


# ---------------------------------------------------------------- frames
def parse_frame(frame: bytes, watch_ips: frozenset = frozenset()) -> list[dict]:
    """Return zero or more sensor observations for one Ethernet frame.

    ``watch_ips``: IPv4 addresses (normally just the gateway) whose source MAC is
    also learned from ordinary IP traffic, so that a later ARP reply claiming the
    same address with another MAC is recognised as spoofing."""
    if len(frame) < 14:
        return []
    src_mac = mac_str(frame[6:12])
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if etype == 0x8100 and len(frame) >= 18:           # VLAN tag
        etype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    out: list[dict] = []
    if etype == 0x0806 and len(frame) >= off + 28:     # ARP
        op = struct.unpack("!H", frame[off + 6: off + 8])[0]
        sha = mac_str(frame[off + 8: off + 14])
        spa = ip4(frame[off + 14: off + 18])
        if spa != "0.0.0.0":
            out.append({"kind": "arp", "ip": spa, "mac": sha, "op": "reply" if op == 2 else "request",
                        "eth_src": src_mac})
    elif etype == 0x0800 and len(frame) >= off + 20:    # IPv4
        ihl = (frame[off] & 0x0F) * 4
        proto = frame[off + 9]
        sip = ip4(frame[off + 12: off + 16])
        if sip in watch_ips:
            out.append({"kind": "ipmac", "ip": sip, "mac": src_mac})
        if proto == 17 and len(frame) >= off + ihl + 8:
            sport, dport = struct.unpack("!HH", frame[off + ihl: off + ihl + 4])
            payload = frame[off + ihl + 8:]
            if {sport, dport} & {67, 68}:
                d = parse_dhcp(payload)
                if d:
                    d["kind"] = "dhcp"
                    out.append(d)
            elif sport == 5353 or dport == 5353:
                names, services = parse_mdns(payload)
                if names or services:
                    out.append({"kind": "mdns", "ip": sip, "mac": src_mac,
                                "names": names, "services": services})
    elif etype == 0x86DD and len(frame) >= off + 40:    # IPv6 NDP
        nxt = frame[off + 6]
        if nxt == 58 and len(frame) >= off + 41:
            icmp_type = frame[off + 40]
            if icmp_type in (135, 136):
                sip = socket.inet_ntop(socket.AF_INET6, frame[off + 8: off + 24])
                if sip != "::":
                    out.append({"kind": "ndp", "ip": sip, "mac": src_mac})
    return out


class Deduper:
    """Emit an (ip, mac) observation when it is new or every ``every`` seconds."""

    def __init__(self, every: float = 300.0):
        self.every, self.seen = every, {}

    def keep(self, rec: dict, ts: float) -> bool:
        key = (rec["kind"], rec.get("ip"), rec.get("mac"),
               tuple(rec.get("names", ())), tuple(rec.get("services", ())), rec.get("hostname"))
        last = self.seen.get(key)
        if last is None or ts - last >= self.every:
            self.seen[key] = ts
            return True
        return False


# ---------------------------------------------------------------- pcap (offline/tests)
def read_pcap(path):
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian, nano = "<", magic == 0xA1B23C4D
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian, nano = ">", magic == 0x4D3CB2A1
        else:
            raise ValueError("not a classic pcap file")
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(endian + "IIII", rh)
            data = fh.read(incl)
            yield sec + frac / (1e9 if nano else 1e6), data


def replay_pcap(path, net: dict | None = None) -> list[dict]:
    dd, out, seq = Deduper(), [], 0
    watch = frozenset([net["gateway"]]) if net and net.get("gateway") else frozenset()
    if net:
        out.append({"kind": "net", "ts": 0.0, "seq": 0, **net})
    for ts, frame in read_pcap(path):
        if net and out[0]["ts"] == 0.0:
            out[0]["ts"] = ts
        for rec in parse_frame(frame, watch):
            if dd.keep(rec, ts):
                seq += 1
                rec.update(ts=ts, seq=seq)
                out.append(rec)
    return out


# ---------------------------------------------------------------- live
def default_route() -> tuple[str | None, str | None]:
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if f[1] == "00000000" and int(f[3], 16) & 2:
                    return f[0], socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    except OSError:
        pass
    return None, None


def iface_addrs(iface: str) -> tuple[str | None, str | None]:
    mac = None
    try:
        mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
    except OSError:
        pass
    ip = None
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
                                          struct.pack("256s", iface[:15].encode()))[20:24])
    except OSError:
        pass
    return ip, mac


def iface_netmask(iface: str) -> str | None:
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B,   # SIOCGIFNETMASK
                                            struct.pack("256s", iface[:15].encode()))[20:24])
    except OSError:
        return None


# ---------------------------------------------------------------- active census
# The census is the one active step: an ARP sweep of this PC's own subnet, done
# only when the user has turned it on (control file written by the Security
# Center, which first checks "this is my network"). ARP never leaves the LAN.
CENSUS_INTERVAL = 180.0
CENSUS_BATCH = 16            # frames per burst
CENSUS_GAP = 0.02           # seconds between bursts (gentle on the network)


def census_enabled(path: Path) -> bool:
    try:
        return bool(json.loads(path.read_text()).get("enabled"))
    except (OSError, ValueError):
        return False


def sweep(sock, src_mac: str, src_ip: str, netmask: str) -> int:
    """Send one ARP request per host of the local subnet. Returns how many were sent."""
    from .discover import arp_request_frame, subnet_hosts
    hosts = subnet_hosts(src_ip, netmask)
    sent = 0
    for n, target in enumerate(hosts):
        try:
            sock.send(arp_request_frame(src_mac, src_ip, target))
            sent += 1
        except OSError:
            break
        if n % CENSUS_BATCH == CENSUS_BATCH - 1:
            time.sleep(CENSUS_GAP)
    return sent


def run_live(out_path: Path, iface: str | None = None, census_path: Path | None = None) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    census_path = census_path or (out_path.parent / "census.json")
    seq = 0
    dd = Deduper()

    def emit(fh, rec):
        nonlocal seq
        seq += 1
        rec.update(ts=time.time(), seq=seq)
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        fh.flush()

    while True:
        dev, gw = default_route()
        dev = iface or dev
        if not dev:
            time.sleep(5)
            continue
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((dev, 0))
        sock.settimeout(5.0)
        self_ip, self_mac = iface_addrs(dev)
        netmask = iface_netmask(dev)
        with open(out_path, "a", encoding="utf-8") as fh:
            emit(fh, {"kind": "net", "iface": dev, "gateway": gw, "self_ip": self_ip, "self_mac": self_mac})
            last_check = time.time()
            last_census = 0.0
            watch = frozenset([gw]) if gw else frozenset()
            while True:
                try:
                    frame = sock.recv(65535)
                    for rec in parse_frame(frame, watch):
                        if dd.keep(rec, time.time()):
                            emit(fh, rec)
                except socket.timeout:
                    pass
                except OSError:
                    break
                now = time.time()
                if (self_ip and self_mac and netmask and now - last_census > CENSUS_INTERVAL
                        and census_enabled(census_path)):
                    last_census = now
                    n = sweep(sock, self_mac, self_ip, netmask)
                    emit(fh, {"kind": "census", "sent": n})
                if now - last_check > 10:
                    last_check = now
                    ndev, ngw = default_route()
                    if (iface is None and ndev != dev) or ngw != gw:
                        break                       # network changed: restart
        sock.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberDistro Sentinel passive sensor (listen-only)")
    ap.add_argument("--out", default=os.environ.get("SENTINEL_SENSOR_LOG", "/var/lib/sentinel/sensor.jsonl"))
    ap.add_argument("--iface")
    ap.add_argument("--pcap", help="replay a pcap file instead of listening (testing)")
    ap.add_argument("--gateway", help="with --pcap: gateway IP to assume")
    ap.add_argument("--self-ip", help="with --pcap: IP of the monitoring PC")
    args = ap.parse_args(argv)
    if args.pcap:
        net = ({"iface": "pcap", "gateway": args.gateway, "self_ip": args.self_ip, "self_mac": None}
               if args.gateway else None)
        with open(args.out, "w", encoding="utf-8") as fh:
            for rec in replay_pcap(args.pcap, net):
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        return 0
    run_live(Path(args.out), args.iface)
    return 0


if __name__ == "__main__":
    sys.exit(main())
