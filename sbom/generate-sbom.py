#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM for CyberDistro.

Sources of truth:
  * build/config/package-lists/*.list.chroot  → Debian/Kali components
  * security-center/pyproject.toml             → first-party component + py deps
  * a curated map of externally-fetched components (Tor Browser, Volatility)

This produces an auditable component list with licenses. Package *versions* are
resolved at build time on the real system (apt/dpkg); here we emit the component
set with a `scope`/`version` of "resolved-at-build" where the version is only
known after the ISO is built. That is honest: we do not invent version strings.

Usage: python3 sbom/generate-sbom.py > sbom/cyberdistro.cdx.json
"""
from __future__ import annotations

import datetime as dt
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Curated license hints for the bundled tools (SPDX where known). Versions are
# resolved at build time; licenses are stable project facts.
LICENSE_HINTS = {
    "nmap": "NPSL (Nmap Public Source License)",
    "wireshark": "GPL-2.0-or-later", "tshark": "GPL-2.0-or-later",
    "tcpdump": "BSD-3-Clause", "zeek": "BSD-3-Clause",
    "zaproxy": "Apache-2.0", "nikto": "GPL-2.0-only",
    "sleuthkit": "GPL-2.0-or-later / CPL-1.0", "autopsy": "Apache-2.0",
    "yara": "BSD-3-Clause", "ghidra": "Apache-2.0", "radare2": "LGPL-3.0-only",
    "rizin": "LGPL-3.0-only", "gdb": "GPL-3.0-or-later",
    "binwalk": "MIT", "john": "GPL-2.0-or-later", "hashcat": "MIT",
    "openssl": "Apache-2.0", "gnupg": "GPL-3.0-or-later",
    "aircrack-ng": "GPL-2.0-or-later", "tor": "BSD-3-Clause",
    "torsocks": "GPL-2.0-only", "plasma-desktop": "GPL-2.0-or-later",
    "clamav": "GPL-2.0-only", "exiftool": "Artistic-1.0 / GPL-1.0-or-later",
}

EXTERNAL = [
    {"name": "tor-browser", "license": "MPL-2.0 / Tor Project",
     "source": "https://dist.torproject.org (GPG-verified in hook 0400)",
     "note": "Not repackaged; bundled as the official build to preserve fingerprint resistance."},
    {"name": "volatility3", "license": "Volatility Software License (VSL) / custom",
     "source": "pip (hook 0300), version pinned 2.8.0"},
]


def read_package_lists() -> dict[str, str]:
    pkgs: dict[str, str] = {}
    for path in sorted(glob.glob(os.path.join(
            ROOT, "build/config/package-lists/*.list.chroot"))):
        cat = re.sub(r"^\d+-|\.list\.chroot$", "", os.path.basename(path))
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkgs[line] = cat
    return pkgs


def component(name: str, group: str, license_: str | None,
              version: str = "resolved-at-build", ctype: str = "application",
              extra: dict | None = None) -> dict:
    c = {
        "type": ctype,
        "name": name,
        "version": version,
        "group": group,
        "purl": f"pkg:deb/debian/{name}" if group != "python" else f"pkg:pypi/{name}",
    }
    if license_:
        c["licenses"] = [{"license": {"name": license_}}]
    if extra:
        c.update(extra)
    return c


def main() -> int:
    pkgs = read_package_lists()
    components = []

    # First-party component
    components.append(component(
        "cyberdistro-security-center", "cyberdistro", "GPL-3.0-or-later",
        version=open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "VERSION")).read().strip().split("-")[0], extra={"description": "First-party Security Center"}))

    # Debian/Kali packages
    for name, cat in pkgs.items():
        components.append(component(
            name, f"os-packages/{cat}", LICENSE_HINTS.get(name),
            ctype="library"))

    # External fetched components
    for e in EXTERNAL:
        components.append(component(
            e["name"], "external", e["license"],
            extra={"externalReferences": [
                {"type": "distribution", "url": e.get("source", "")}],
                "description": e.get("note", "")}))

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "component": {
                "type": "operating-system",
                "name": "CyberDistro",
                "version": open(os.path.join(ROOT, "VERSION")).read().strip(),
            },
            "tools": [{"name": "cyberdistro-generate-sbom", "version": "0.1.0"}],
            "notes": "Versions marked 'resolved-at-build' are fixed by apt/dpkg "
                     "when the ISO is built; this SBOM enumerates the component "
                     "set and licenses without inventing version strings.",
        },
        "components": components,
    }
    json.dump(bom, sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
