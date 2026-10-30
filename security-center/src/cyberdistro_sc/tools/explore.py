"""«Esplora» — visual, beginner-friendly discovery of what is around you.

Two questions a non-expert asks first:
  * "Who is on my Wi‑Fi / network?"  → local network discovery
  * "Which Bluetooth devices are nearby?" → Bluetooth discovery

This module answers both with real tools (nmap, iproute2, bluez) and returns
*structured devices* with a type and an icon, so the GUI can show them as
clickable tiles. Everything that parses tool output is a pure function and is
unit-tested against real sample outputs.

Safety model (deliberately narrower than the professional tools):
  * Network discovery is restricted to the **local networks this machine is
    connected to** (derived from `ip addr`/`ip route`). You cannot type an
    arbitrary target here — that is what the professional Nmap inventory is
    for, with a declared project scope.
  * Even so it is an *active* operation (ping sweep), so the caller must still
    pass an Authorization that covers the local network. `local_authorization`
    builds one once the user has confirmed, in the UI, that this is their own
    network or one they are allowed to inspect. The confirmation is recorded.
  * Very large local prefixes are capped to the /24 around our own address, so
    a misconfigured /8 never turns into a sweep of millions of addresses.
  * Bluetooth discovery is passive listening for advertisements; it never
    pairs, connects or sends anything to the devices found.
  * No root required. With root, nmap also reports MAC vendors directly; without
    it we read MACs from the kernel neighbour table and resolve vendors from
    nmap's OUI database on disk.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Callable

from ..core.authorization import Authorization, ActivityKind
from ..core.runner import CommandPlan

TOOL_ID = "explore"
MAX_PREFIX_HOSTS = 24          # never sweep more than a /24 at a time
NMAP_OUI_PATHS = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
)

# Device kind → (freedesktop icon name, Italian label, English label)
KINDS: dict[str, tuple[str, str, str]] = {
    "self":     ("computer-laptop",            "Questo computer",     "This computer"),
    "router":   ("network-wireless-router",    "Router / gateway",    "Router / gateway"),
    "computer": ("computer",                   "Computer",            "Computer"),
    "phone":    ("smartphone",                 "Telefono / tablet",   "Phone / tablet"),
    "printer":  ("printer",                    "Stampante",           "Printer"),
    "tv":       ("video-television",           "TV / media player",   "TV / media player"),
    "camera":   ("camera-web",                 "Videocamera",         "Camera"),
    "audio":    ("audio-headphones",           "Audio",               "Audio device"),
    "input":    ("input-keyboard",             "Tastiera / mouse",    "Keyboard / mouse"),
    "wearable": ("preferences-desktop-user",   "Indossabile",         "Wearable"),
    "iot":      ("network-wired",              "Dispositivo smart",   "Smart device"),
    "unknown":  ("network-workgroup",          "Dispositivo",         "Device"),
}


# Alternative theme icon names per kind, in order of preference. Verified
# against the Papirus set shipped in the ISO (64x64/devices): e.g. Papirus has
# "phone" and "network-modem" but no "smartphone"/"network-wireless-router".
ICON_ALTERNATES: dict[str, list[str]] = {
    "self":     ["computer-laptop", "computer"],
    "router":   ["network-wireless-router", "network-modem", "network-server"],
    "computer": ["computer", "computer-laptop"],
    "phone":    ["smartphone", "phone", "tablet"],
    "printer":  ["printer", "printer-network"],
    "tv":       ["video-television", "tv"],
    "camera":   ["camera-web", "camera-video", "camera-photo"],
    "audio":    ["audio-headphones", "audio-speakers", "audio-card"],
    "input":    ["input-keyboard", "input-mouse"],
    "wearable": ["smartwatch", "preferences-desktop-user", "phone"],
    "iot":      ["network-wired", "network-card"],
    "unknown":  ["network-workgroup", "network-card", "network-wired"],
}


def icon_for(kind: str) -> str:
    return KINDS.get(kind, KINDS["unknown"])[0]


def icon_candidates(kind: str) -> list[str]:
    """Theme icon names to try, most specific first (GUI falls back to a glyph)."""
    names = list(ICON_ALTERNATES.get(kind, []))
    primary = icon_for(kind)
    if primary not in names:
        names.insert(0, primary)
    return names


def label_for(kind: str, lang: str = "it") -> str:
    row = KINDS.get(kind, KINDS["unknown"])
    return row[1] if lang == "it" else row[2]


# ----------------------------------------------------------------- helpers
Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def _run(argv: list[str], timeout: float = 30.0) -> "subprocess.CompletedProcess[str]":
    """Run a command without a shell; never raises on missing binaries."""
    if shutil.which(argv[0]) is None:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not installed")
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        return subprocess.CompletedProcess(argv, -1, out or "", "timed out")


# ---------------------------------------------------------- local networks
@dataclass
class LocalNetwork:
    interface: str
    kind: str                  # wifi | ethernet | other
    address: str               # our IPv4 address
    cidr: str                  # network to explore (possibly capped)
    gateway: str = ""
    ssid: str = ""
    capped: bool = False       # True if the real prefix was wider than /24

    @property
    def title(self) -> str:
        if self.kind == "wifi" and self.ssid:
            return f"Wi‑Fi «{self.ssid}»"
        if self.kind == "wifi":
            return f"Wi‑Fi ({self.interface})"
        if self.kind == "ethernet":
            return f"Rete cablata ({self.interface})"
        return f"Rete ({self.interface})"

    def to_dict(self) -> dict:
        return asdict(self)


def _is_wireless(iface: str) -> bool:
    return (os.path.isdir(f"/sys/class/net/{iface}/wireless")
            or os.path.exists(f"/sys/class/net/{iface}/phy80211"))


def cap_network(address: str, prefixlen: int) -> tuple[str, bool]:
    """Return (cidr, capped). Prefixes wider than /24 are reduced to the /24
    that contains our address so a sweep stays small and fast."""
    if prefixlen < MAX_PREFIX_HOSTS:
        net = ipaddress.ip_network(f"{address}/{MAX_PREFIX_HOSTS}", strict=False)
        return str(net), True
    net = ipaddress.ip_network(f"{address}/{prefixlen}", strict=False)
    return str(net), False


def parse_ip_addr(json_text: str, is_wireless=None) -> list[LocalNetwork]:
    """Parse `ip -j addr show` output into candidate local networks (IPv4 only)."""
    is_wireless = is_wireless or _is_wireless
    nets: list[LocalNetwork] = []
    try:
        data = json.loads(json_text or "[]")
    except json.JSONDecodeError:
        return nets
    skip = re.compile(r"^(lo|docker\d*|br-|veth|virbr|tun|tap|tor|wg|vmnet)")
    for link in data:
        name = link.get("ifname", "")
        if not name or skip.match(name):
            continue
        if link.get("operstate") not in ("UP", "UNKNOWN"):
            continue
        for a in link.get("addr_info", []):
            if a.get("family") != "inet" or a.get("scope") != "global":
                continue
            addr, plen = a.get("local"), int(a.get("prefixlen", 32))
            if not addr or plen >= 31:
                continue
            cidr, capped = cap_network(addr, plen)
            kind = "wifi" if is_wireless(name) else (
                "ethernet" if re.match(r"^(en|eth)", name) else "other")
            nets.append(LocalNetwork(interface=name, kind=kind, address=addr,
                                     cidr=cidr, capped=capped))
    return nets


def parse_ip_route_gateways(json_text: str) -> dict[str, str]:
    """`ip -j route show default` → {interface: gateway}."""
    out: dict[str, str] = {}
    try:
        for r in json.loads(json_text or "[]"):
            if r.get("dst") == "default" and r.get("dev") and r.get("gateway"):
                out.setdefault(r["dev"], r["gateway"])
    except json.JSONDecodeError:
        pass
    return out


def parse_iw_ssid(text: str) -> str:
    m = re.search(r"^\s*SSID:\s*(.+)$", text or "", re.MULTILINE)
    return m.group(1).strip() if m else ""


def local_networks(run: Runner = _run) -> list[LocalNetwork]:
    """Networks this machine is currently attached to (IPv4)."""
    nets = parse_ip_addr(run(["ip", "-j", "addr", "show"]).stdout)
    gws = parse_ip_route_gateways(run(["ip", "-j", "route", "show", "default"]).stdout)
    for n in nets:
        n.gateway = gws.get(n.interface, "")
        if n.kind == "wifi":
            n.ssid = parse_iw_ssid(run(["iw", "dev", n.interface, "link"]).stdout)
            if not n.ssid:
                p = run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"])
                for line in (p.stdout or "").splitlines():
                    if line.startswith("yes:"):
                        n.ssid = line.split(":", 1)[1]
                        break
    # Prefer the network that owns the default route first.
    nets.sort(key=lambda n: (not n.gateway, n.kind != "wifi", n.interface))
    return nets


def local_authorization(net: LocalNetwork, owner: str,
                        confirmed: bool) -> Authorization:
    """Build the scoped authorization for exploring *this* local network.

    ``confirmed`` must be the result of an explicit user confirmation ("this
    is my network or I am allowed to inspect it"). Without it the scope is
    empty and any active operation is refused by Authorization.require().
    """
    scope = [net.cidr] if confirmed else []
    return Authorization(
        project="Esplora — rete locale",
        owner=owner or "utente",
        scope=scope,
        note=("Esplorazione limitata alla rete locale a cui questo computer è "
              f"connesso ({net.title}). L'utente ha dichiarato di esserne "
              "proprietario o di essere autorizzato a osservarla."),
    )


# ------------------------------------------------------------------ devices
@dataclass
class Device:
    address: str                     # IPv4 (network) or MAC (bluetooth)
    name: str = ""                   # hostname / BT name
    mac: str = ""
    vendor: str = ""
    kind: str = "unknown"
    source: str = "network"          # network | bluetooth
    details: dict = field(default_factory=dict)
    seen_at: float = field(default_factory=time.time)

    @property
    def icon(self) -> str:
        return icon_for(self.kind)

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.vendor:
            return self.vendor
        return self.address

    def to_dict(self) -> dict:
        d = asdict(self)
        d["icon"] = self.icon
        d["display_name"] = self.display_name
        return d


_PHONE = re.compile(r"iphone|ipad|android|galaxy|pixel|xiaomi|redmi|huawei|oneplus|oppo|"
                    r"vivo|motorola|realme|honor|samsung", re.I)
_PRINTER = re.compile(r"printer|hp[ -]?(laserjet|officejet|deskjet|envy)|epson|brother|"
                      r"canon|lexmark|kyocera|ricoh|xerox", re.I)
_TV = re.compile(r"\btv\b|bravia|chromecast|roku|fire ?tv|apple ?tv|shield|lg ?webos|"
                 r"hisense|philips ?tv|sonos|vizio|tcl", re.I)
_ROUTER = re.compile(r"router|gateway|fritz|tp-?link|netgear|asus|linksys|ubiquiti|"
                     r"mikrotik|zyxel|technicolor|sagemcom|avm|d-link|huawei ?tech|"
                     r"zte|arris|vodafone|tim|fastweb|iliad", re.I)
_CAMERA = re.compile(r"cam|hikvision|dahua|reolink|arlo|ring|nest ?cam|wyze|tapo", re.I)
_IOT = re.compile(r"espressif|esp32|esp8266|tuya|shelly|sonoff|raspberry|rasp|tasmota|"
                  r"philips ?hue|signify|nest|amazon|echo|alexa|google ?home", re.I)
_COMPUTER = re.compile(r"apple|dell|lenovo|hewlett|hp inc|asus|acer|msi|intel|"
                       r"microsoft|macbook|imac|desktop|laptop|pc\b|think", re.I)


def classify(name: str = "", vendor: str = "", is_gateway: bool = False,
             is_self: bool = False) -> str:
    """Best-effort device type from hostname/vendor. Conservative: 'unknown'
    when nothing matches — the UI must never pretend to know more than it does."""
    if is_self:
        return "self"
    if is_gateway:
        return "router"
    hay = f"{name} {vendor}"
    if _PRINTER.search(hay):
        return "printer"
    if _PHONE.search(hay):
        return "phone"
    if _TV.search(hay):
        return "tv"
    if _CAMERA.search(hay):
        return "camera"
    if _ROUTER.search(hay):
        return "router"
    if _IOT.search(hay):
        return "iot"
    if _COMPUTER.search(hay):
        return "computer"
    return "unknown"


# ------------------------------------------------------------ MAC → vendor
_OUI_CACHE: dict[str, str] | None = None


def load_oui_db(path: str | None = None) -> dict[str, str]:
    """Load nmap's OUI table ("prefix vendor" per line, prefix = 6 hex chars)."""
    paths = [path] if path else list(NMAP_OUI_PATHS)
    db: dict[str, str] = {}
    for p in paths:
        if p and os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and len(parts[0]) == 6:
                        db[parts[0].upper()] = parts[1].strip()
            break
    return db


def lookup_vendor(mac: str, db: dict[str, str] | None = None) -> str:
    global _OUI_CACHE
    if not mac:
        return ""
    if db is None:
        if _OUI_CACHE is None:
            _OUI_CACHE = load_oui_db()
        db = _OUI_CACHE
    key = re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper()
    # Locally administered (randomised) MACs have no vendor by design.
    try:
        if int(key[:2], 16) & 0x02:
            return ""
    except ValueError:
        return ""
    return db.get(key, "")


# -------------------------------------------------------- network discovery
def plan_network_scan(cidr: str) -> CommandPlan:
    """Ping sweep only: no port scan, no scripts. Bounded timing."""
    return CommandPlan(
        tool_id=TOOL_ID,
        argv=["nmap", "-sn", "-T3", "-oX", "-", cidr],
        description="Scopri quali dispositivi sono attivi sulla rete locale "
                    "(solo rilevamento presenza, nessuna porta).",
        needs_privilege=False,
        activity=ActivityKind.ACTIVE_LIGHT.value,
    )


def parse_nmap_hosts(xml_text: str) -> list[dict]:
    """Nmap -sn XML → [{address, mac, vendor, hostname}] for hosts that are up."""
    hosts: list[dict] = []
    if not (xml_text or "").strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        rec = {"address": "", "mac": "", "vendor": "", "hostname": ""}
        for a in h.findall("address"):
            t = a.get("addrtype")
            if t == "ipv4" and not rec["address"]:
                rec["address"] = a.get("addr", "")
            elif t == "mac":
                rec["mac"] = a.get("addr", "").upper()
                rec["vendor"] = a.get("vendor", "")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            rec["hostname"] = hn.get("name", "")
        if rec["address"]:
            hosts.append(rec)
    return hosts


def parse_ip_neigh(json_text: str) -> dict[str, str]:
    """`ip -j neigh show` → {ipv4: MAC} for reachable/stale entries."""
    out: dict[str, str] = {}
    try:
        for n in json.loads(json_text or "[]"):
            mac = n.get("lladdr")
            dst = n.get("dst", "")
            if mac and dst and ":" not in dst and "FAILED" not in n.get("state", []):
                out[dst] = mac.upper()
    except json.JSONDecodeError:
        pass
    return out


def scan_network(net: LocalNetwork, auth: Authorization,
                 run: Runner = _run, timeout: float = 180.0,
                 oui_db: dict[str, str] | None = None) -> tuple[CommandPlan, "subprocess.CompletedProcess[str]", list[Device]]:
    """Authorize, sweep the local network, enrich with MAC/vendor, classify.

    Raises AuthorizationError if ``auth`` does not cover ``net.cidr``.
    Returns (plan, raw process result, devices) — the plan is shown to the
    user and recorded so the operation is always reproducible.
    """
    auth.require(net.cidr, ActivityKind.ACTIVE_LIGHT)
    plan = plan_network_scan(net.cidr)
    proc = run(plan.argv, timeout)
    hosts = parse_nmap_hosts(proc.stdout)
    neigh = parse_ip_neigh(run(["ip", "-j", "neigh", "show", "dev", net.interface]).stdout)

    devices: list[Device] = []
    for h in hosts:
        mac = h["mac"] or neigh.get(h["address"], "")
        vendor = h["vendor"] or lookup_vendor(mac, oui_db)
        is_self = h["address"] == net.address
        is_gw = bool(net.gateway) and h["address"] == net.gateway
        kind = classify(h["hostname"], vendor, is_gateway=is_gw, is_self=is_self)
        devices.append(Device(
            address=h["address"], name=h["hostname"], mac=mac, vendor=vendor,
            kind=kind, source="network",
            details={
                "rete": net.cidr, "interfaccia": net.interface,
                "gateway": "sì" if is_gw else "no",
                "questo computer": "sì" if is_self else "no",
                "mac_random": "sì" if (mac and int(mac[:2], 16) & 0x02) else "no",
            },
        ))
    # Self first, then router, then the rest by address.
    order = {"self": 0, "router": 1}
    devices.sort(key=lambda d: (order.get(d.kind, 2), _ip_key(d.address)))
    return plan, proc, devices


def _ip_key(addr: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_address(addr)))
    except ValueError:
        return (1, addr)


# ------------------------------------------------------ bluetooth discovery
_BT_ICON_TO_KIND = {
    "phone": "phone", "computer": "computer", "audio-card": "audio",
    "audio-headset": "audio", "audio-headphones": "audio", "audio-speakers": "audio",
    "input-keyboard": "input", "input-mouse": "input", "input-gaming": "input",
    "input-tablet": "input", "printer": "printer", "camera-photo": "camera",
    "camera-video": "camera", "video-display": "tv", "multimedia-player": "tv",
    "network-wireless": "router", "modem": "router", "scanner": "printer",
}


def bluetooth_available(run: Runner = _run) -> tuple[bool, str]:
    """(available, reason). Requires bluez's bluetoothctl and a controller."""
    if shutil.which("bluetoothctl") is None:
        return False, "bluetoothctl (bluez) non installato"
    p = run(["bluetoothctl", "list"], 10)
    if p.returncode != 0 or not (p.stdout or "").strip():
        return False, "nessun adattatore Bluetooth rilevato (o servizio bluetooth non attivo)"
    return True, ""


def plan_bluetooth_scan(seconds: int = 8) -> CommandPlan:
    return CommandPlan(
        tool_id=TOOL_ID,
        argv=["bluetoothctl", "--timeout", str(int(seconds)), "scan", "on"],
        description="Ascolta per alcuni secondi i dispositivi Bluetooth che si "
                    "annunciano nelle vicinanze (nessuna connessione).",
        needs_privilege=False,
        activity=ActivityKind.PASSIVE.value,
    )


_BT_DEVICE_RE = re.compile(r"^Device\s+([0-9A-Fa-f:]{17})\s*(.*)$", re.MULTILINE)


def parse_bluetoothctl_devices(text: str) -> list[tuple[str, str]]:
    """`bluetoothctl devices` → [(MAC, name)] (name may equal the MAC)."""
    out = []
    for m in _BT_DEVICE_RE.finditer(text or ""):
        mac, name = m.group(1).upper(), m.group(2).strip()
        if name.replace("-", ":").upper() == mac:
            name = ""
        out.append((mac, name))
    return out


def parse_bluetoothctl_info(text: str) -> dict:
    """`bluetoothctl info <MAC>` → flat dict of the interesting fields."""
    info: dict = {"uuids": []}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("Device "):
            parts = line.split()
            if len(parts) >= 2:
                info["mac"] = parts[1].upper()
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip(), val.strip()
        if key == "UUID":
            info["uuids"].append(val)
        elif key in ("Name", "Alias", "Icon", "Class", "Paired", "Trusted",
                     "Connected", "Blocked", "RSSI", "ManufacturerData Key",
                     "Address Type", "Appearance", "Modalias", "Battery Percentage"):
            info[key] = val
    return info


def _bt_kind(info: dict) -> str:
    icon = (info.get("Icon") or "").lower()
    if icon in _BT_ICON_TO_KIND:
        return _BT_ICON_TO_KIND[icon]
    name = f"{info.get('Name','')} {info.get('Alias','')}"
    if re.search(r"watch|band|fit", name, re.I):
        return "wearable"
    if re.search(r"buds|airpods|headphone|speaker|jbl|bose|sony wh|soundcore", name, re.I):
        return "audio"
    return classify(name)


def scan_bluetooth(seconds: int = 8, run: Runner = _run,
                   oui_db: dict[str, str] | None = None) -> tuple[CommandPlan, list[Device], str]:
    """Listen for nearby Bluetooth devices. Returns (plan, devices, error)."""
    ok, why = bluetooth_available(run)
    plan = plan_bluetooth_scan(seconds)
    if not ok:
        return plan, [], why
    # Make sure the controller is powered (idempotent, no pairing involved).
    run(["bluetoothctl", "power", "on"], 10)
    run(plan.argv, seconds + 10)
    listing = run(["bluetoothctl", "devices"], 10)
    devices: list[Device] = []
    for mac, name in parse_bluetoothctl_devices(listing.stdout):
        info = parse_bluetoothctl_info(run(["bluetoothctl", "info", mac], 10).stdout)
        bt_name = info.get("Name") or info.get("Alias") or name
        if bt_name.replace("-", ":").upper() == mac:
            bt_name = ""            # alias is just the address → no real name
        vendor = lookup_vendor(mac, oui_db)
        kind = _bt_kind({**info, "Name": bt_name})
        details = {
            "tipo bluetooth": info.get("Icon", "") or "n/d",
            "accoppiato": "sì" if info.get("Paired") == "yes" else "no",
            "connesso": "sì" if info.get("Connected") == "yes" else "no",
            "segnale (RSSI)": info.get("RSSI", "n/d"),
            "tipo indirizzo": info.get("Address Type", "n/d"),
            "servizi annunciati": str(len(info.get("uuids", []))),
        }
        if info.get("Battery Percentage"):
            details["batteria"] = info["Battery Percentage"]
        devices.append(Device(address=mac, name=bt_name, mac=mac, vendor=vendor,
                              kind=kind, source="bluetooth", details=details))
    devices.sort(key=lambda d: (d.kind == "unknown", d.display_name.lower()))
    return plan, devices, ""


def explain() -> dict:
    return {
        "what_it_does": "Mostra in modo visuale chi c'è sulla tua rete Wi‑Fi/cablata "
                        "e quali dispositivi Bluetooth sono nelle vicinanze.",
        "when": "Per capire quali dispositivi sono collegati alla tua rete di casa o "
                "ufficio, o chi ti circonda via Bluetooth.",
        "permissions": "Solo reti a cui questo computer è connesso e di cui dichiari "
                       "di essere proprietario/autorizzato. Nessun privilegio di root.",
        "note": "Il rilevamento di rete è ATTIVO (ping) ma leggero; il Bluetooth è "
                "solo in ascolto. Il tipo di dispositivo è una stima: quando non è "
                "riconoscibile viene mostrato come generico.",
    }
