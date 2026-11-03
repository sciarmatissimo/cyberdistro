"""Device naming helpers: vendor from the MAC prefix (IEEE OUI list shipped by
Debian's ieee-data) and a coarse device type. Types are hints for the network
map, shown as "probabile" — never used for detection."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

OUI_FILES = ("/usr/share/ieee-data/oui.txt",)

TYPE_LABEL = {"it": {"router": "Router", "pc": "Computer", "phone": "Telefono", "printer": "Stampante",
                     "tv": "TV / media", "iot": "Dispositivo smart", "unknown": "Sconosciuto", "self": "Questo PC"},
              "en": {"router": "Router", "pc": "Computer", "phone": "Phone", "printer": "Printer",
                     "tv": "TV / media", "iot": "Smart device", "unknown": "Unknown", "self": "This PC"}}


@lru_cache(maxsize=1)
def _oui() -> dict:
    out = {}
    for f in OUI_FILES:
        p = Path(f)
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if "(hex)" in line:
                pre, _, vendor = line.partition("(hex)")
                out[pre.strip().replace("-", ":").lower()] = vendor.strip()
    return out


def vendor(mac: str | None) -> str | None:
    if not mac or len(mac) < 8:
        return None
    first = int(mac[:2], 16)
    if first & 0x02:
        return "indirizzo casuale (privacy)"     # locally administered: phones randomise MACs
    return _oui().get(mac[:8].lower())


def guess_type(d: dict) -> str:
    if d.get("is_self"):
        return "self"
    if d.get("is_gateway"):
        return "router"
    v = (vendor(d.get("mac")) or "").lower()
    names = " ".join([d.get("hostname") or ""] + list(d.get("mdns") or [])).lower()
    svc = " ".join(d.get("services") or []).lower()
    if any(s in svc for s in ("_ipp", "_printer", "_pdl-datastream")) or any(
            k in v for k in ("brother", "epson", "canon", "kyocera", "lexmark")):
        return "printer"
    if any(s in svc for s in ("_googlecast", "_airplay", "_raop", "_spotify")) or any(
            k in names for k in ("tv", "chromecast", "roku", "firetv")):
        return "tv"
    if any(k in names for k in ("iphone", "ipad", "android", "galaxy", "pixel", "redmi")) or \
            "casuale" in v:
        return "phone"
    if any(k in v for k in ("espressif", "tuya", "shelly", "sonoff", "raspberry", "nest")):
        return "iot"
    if any(k in v for k in ("intel", "dell", "lenovo", "hewlett", "asustek", "micro-star", "apple", "giga-byte")) \
            or any(s in svc for s in ("_ssh", "_smb", "_workstation")):
        return "pc"
    return "unknown"
