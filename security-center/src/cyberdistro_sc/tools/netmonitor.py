"""«Monitor di rete (bridge trasparente)» — turn a 2-NIC PC into an inline,
read-only network tap, with a beginner-friendly guided flow.

The PC is placed *in the cable* between two segments (e.g. router ↔ rest of the
LAN). The two network cards are joined into a layer-2 **bridge** with no IP of
its own, so the box is transparent: traffic passes through unchanged and can be
observed. We then:
  * open Wireshark on the bridge with a sensible display filter, and
  * run a lightweight `tshark` summary that feeds a *visual* view — one tile per
    device seen, and the list of sites (domains) contacted.

Design rules, consistent with the rest of CyberDistro:
  * **Passive by default.** We only observe. No TLS interception, no injection.
    What you read is mostly metadata (who talks to whom, which domains, DNS),
    not the encrypted contents.
  * **Authorized use only.** The wizard requires the user to confirm this is
    their own network / they are allowed to monitor it before anything starts.
  * **Honest & reproducible.** Every privileged action is an explicit argv list
    run through one auditable helper (`cyberdistro-netbridge`) via pkexec; the
    exact commands are shown in Professional/Expert mode.
  * **Safe bridging.** We refuse to enslave the interface that currently holds
    the default route (that is usually the box's own management link), unless
    forced, so the wizard can't accidentally cut the operator off.

Everything that parses tool output is a pure function and is unit-tested.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict

BRIDGE_HELPER = "/usr/local/sbin/cyberdistro-netbridge"
BRIDGE_NAME = "br0"

# tshark fields we pull for the live summary (tab-separated, one row per packet).
TSHARK_FIELDS = ["eth.src", "ip.src", "ip.dst",
                 "dns.qry.name", "tls.handshake.extensions_server_name", "http.host"]

# A deliberately readable Wireshark display filter: the things a beginner can
# actually make sense of — name lookups, the site behind an HTTPS connection,
# and plain-HTTP requests. (It filters the *view*, not the capture.)
WIRESHARK_DISPLAY_FILTER = ("dns || tls.handshake.extensions_server_name "
                            "|| http.request")

_SKIP_IFACE = re.compile(r"^(lo|docker\d*|br-|veth|virbr|tun|tap|wg|tor|vmnet|"
                         r"bluetooth|sit|gre)")


# ----------------------------------------------------------------- helpers
def _run(argv, timeout=20.0):
    if shutil.which(argv[0]) is None:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not installed")
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(argv, -1, (e.stdout or ""), "timed out")


# ------------------------------------------------------------- interfaces
@dataclass
class Interface:
    name: str
    mac: str = ""
    kind: str = "other"           # wired | wifi | other
    carrier: bool = False         # a cable/link is actually present
    addresses: list = field(default_factory=list)
    is_default_route: bool = False

    @property
    def has_ip(self) -> bool:
        return bool(self.addresses)

    def title(self, lang: str = "it") -> str:
        kinds = {"wired": ("Rete cablata", "Wired"), "wifi": ("Wi‑Fi", "Wi‑Fi"),
                 "other": ("Interfaccia", "Interface")}
        base = kinds.get(self.kind, kinds["other"])[0 if lang == "it" else 1]
        link = ("cavo collegato" if self.carrier else "nessun cavo") if lang == "it" \
            else ("cable connected" if self.carrier else "no cable")
        return f"{base} · {self.name} ({link})"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["has_ip"] = self.has_ip
        return d


def _is_wireless(name: str) -> bool:
    import os
    return (os.path.isdir(f"/sys/class/net/{name}/wireless")
            or os.path.exists(f"/sys/class/net/{name}/phy80211"))


def parse_interfaces(link_json: str, addr_json: str, route_json: str,
                     is_wireless=_is_wireless) -> list[Interface]:
    """Parse `ip -j link`, `ip -j addr`, `ip -j route` into bridgeable NICs.

    A bridgeable NIC is a real, physical Ethernet/Wi‑Fi interface — not
    loopback, not a virtual/bridge/tunnel device, and not already a bridge port.
    """
    out: list[Interface] = []
    try:
        links = json.loads(link_json or "[]")
    except json.JSONDecodeError:
        return out
    # addresses
    addr_map: dict[str, list] = {}
    try:
        for a in json.loads(addr_json or "[]"):
            name = a.get("ifname", "")
            ips = [f"{i.get('local')}/{i.get('prefixlen')}"
                   for i in a.get("addr_info", []) if i.get("family") == "inet"]
            if ips:
                addr_map[name] = ips
    except json.JSONDecodeError:
        pass
    # default route interface(s)
    default_ifs: set[str] = set()
    try:
        for r in json.loads(route_json or "[]"):
            if r.get("dst") == "default" and r.get("dev"):
                default_ifs.add(r["dev"])
    except json.JSONDecodeError:
        pass

    for link in links:
        name = link.get("ifname", "")
        if not name or _SKIP_IFACE.match(name):
            continue
        if link.get("link_type") not in ("ether", None):
            continue
        # already a bridge port? skip (can't enslave twice)
        if link.get("master"):
            continue
        # a bridge device itself has info_kind == bridge
        if (link.get("linkinfo", {}) or {}).get("info_kind") == "bridge":
            continue
        carrier = link.get("operstate") == "UP" or "LOWER_UP" in link.get("flags", [])
        kind = "wifi" if is_wireless(name) else (
            "wired" if re.match(r"^(en|eth)", name) else "other")
        out.append(Interface(
            name=name, mac=link.get("address", ""), kind=kind, carrier=carrier,
            addresses=addr_map.get(name, []), is_default_route=name in default_ifs))
    out.sort(key=lambda i: (not i.carrier, i.kind != "wired", i.name))
    return out


def list_interfaces(run=_run) -> list[Interface]:
    return parse_interfaces(
        run(["ip", "-j", "link", "show"]).stdout,
        run(["ip", "-j", "addr", "show"]).stdout,
        run(["ip", "-j", "route", "show"]).stdout,
    )


# ------------------------------------------------------ command construction
def plan_bridge_create(if1: str, if2: str, *, privileged: bool = True,
                       force: bool = False) -> list[str]:
    argv = [BRIDGE_HELPER, "create", if1, if2]
    if force:
        argv.append("--force")
    return (["pkexec", *argv] if privileged else argv)


def plan_bridge_destroy(*, privileged: bool = True) -> list[str]:
    argv = [BRIDGE_HELPER, "destroy"]
    return (["pkexec", *argv] if privileged else argv)


def plan_bridge_status(*, privileged: bool = True) -> list[str]:
    argv = [BRIDGE_HELPER, "status"]
    return (["pkexec", *argv] if privileged else argv)


def plan_wireshark(iface: str = BRIDGE_NAME,
                   display_filter: str = WIRESHARK_DISPLAY_FILTER) -> list[str]:
    # -k: start capturing immediately; -Y: display filter. Needs dumpcap privs
    # (the live user is in the 'wireshark' group, configured at build time).
    return ["wireshark", "-i", iface, "-k", "-Y", display_filter]


def plan_tshark_summary(iface: str = BRIDGE_NAME, count: int = 0) -> list[str]:
    argv = ["tshark", "-l", "-n", "-i", iface, "-T", "fields"]
    for f in TSHARK_FIELDS:
        argv += ["-e", f]
    argv += ["-E", "separator=/t"]
    if count:
        argv += ["-c", str(count)]
    return argv


# --------------------------------------------------------- summary parsing
@dataclass
class SeenDevice:
    mac: str = ""
    ip: str = ""
    packets: int = 0
    sites: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"mac": self.mac, "ip": self.ip, "packets": self.packets,
                "sites": sorted(self.sites)}


@dataclass
class SeenSite:
    name: str
    hits: int = 0
    clients: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"name": self.name, "hits": self.hits, "clients": sorted(self.clients)}


def _clean_site(name: str) -> str:
    name = (name or "").strip().rstrip(".").lower()
    # tshark can emit comma-separated lists when several records are in a packet
    if "," in name:
        name = name.split(",")[0].strip()
    return name


class TrafficSummary:
    """Incrementally aggregates tshark field rows into devices and sites."""

    def __init__(self):
        self.devices: dict[str, SeenDevice] = {}   # key: ip or mac
        self.sites: dict[str, SeenSite] = {}

    def feed_line(self, line: str) -> None:
        parts = (line.rstrip("\n").split("\t") + [""] * 6)[:6]
        eth_src, ip_src, ip_dst, dns_q, sni, http_host = parts
        key = ip_src or eth_src
        if key:
            dev = self.devices.get(key)
            if dev is None:
                dev = SeenDevice(mac=eth_src, ip=ip_src)
                self.devices[key] = dev
            dev.packets += 1
            if not dev.mac and eth_src:
                dev.mac = eth_src
            if not dev.ip and ip_src:
                dev.ip = ip_src
        site = _clean_site(sni) or _clean_site(http_host) or _clean_site(dns_q)
        if site and "." in site:
            s = self.sites.get(site)
            if s is None:
                s = SeenSite(name=site)
                self.sites[site] = s
            s.hits += 1
            if key:
                s.clients.add(key)
                self.devices[key].sites.add(site)

    def feed(self, text: str) -> None:
        for line in text.splitlines():
            if line.strip():
                self.feed_line(line)

    def top_devices(self, n: int = 50) -> list[SeenDevice]:
        return sorted(self.devices.values(), key=lambda d: -d.packets)[:n]

    def top_sites(self, n: int = 50) -> list[SeenSite]:
        return sorted(self.sites.values(), key=lambda s: -s.hits)[:n]


def parse_summary(text: str) -> TrafficSummary:
    s = TrafficSummary()
    s.feed(text)
    return s


# ---------------------------------------------------- execution (injectable)
def run_bridge(argv, runner=subprocess.run):
    return runner(argv, capture_output=True, text=True, timeout=60)


def run_capture(argv, spawner=subprocess.Popen):
    return spawner(argv)


def tshark_available(run=_run) -> bool:
    return shutil.which("tshark") is not None


def wireshark_available() -> bool:
    return shutil.which("wireshark") is not None
