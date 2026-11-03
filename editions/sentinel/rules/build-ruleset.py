#!/usr/bin/env python3
"""Build the reduced Suricata rule set shipped in CyberDistro Sentinel.

Input : the Emerging Threats Open tarball for Suricata 7 (emerging.rules.tar.gz)
Output: sentinel.rules — selected categories, rules that ET ships commented out
        in those categories re-enabled, known-noisy rules removed (disable.txt).

Why reduced: the complete ET Open set (≈52 800 rules) used 573 MiB of RAM in
our test; this selection used 389 MiB and detected the same synthetic beacon
plus DNS DGA/tunnel patterns that the complete default set did not flag.
"""

import io
import re
import sys
import tarfile
from pathlib import Path

CATEGORIES = [
    "emerging-scan", "emerging-dns", "emerging-malware", "emerging-mobile_malware",
    "emerging-coinminer", "emerging-exploit", "emerging-attack_response",
    "emerging-hunting", "emerging-policy", "emerging-worm", "emerging-phishing",
    "emerging-current_events", "emerging-trojan", "emerging-ja3", "emerging-dos",
    "emerging-botcc", "emerging-ciarmy", "emerging-compromised", "emerging-tor",
]

SID_RE = re.compile(r"\bsid:\s*(\d+)\s*;")


def main(tarball: str, out: str, disable_file: str) -> int:
    disabled = set()
    for line in Path(disable_file).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line.isdigit():
            disabled.add(line)
    kept, dropped = [], 0
    with tarfile.open(tarball) as tf:
        for m in tf.getmembers():
            name = Path(m.name).name
            if not name.endswith(".rules") or name[:-6] not in CATEGORIES:
                continue
            for raw in io.TextIOWrapper(tf.extractfile(m), encoding="utf-8", errors="replace"):
                line = raw.rstrip("\n")
                if line.startswith("#alert "):
                    line = line[1:]
                if not line.startswith("alert "):
                    continue
                sid = SID_RE.search(line)
                if sid and sid.group(1) in disabled:
                    dropped += 1
                    continue
                kept.append(line)
    Path(out).write_text("\n".join(kept) + "\n")
    print(f"sentinel.rules: {len(kept)} rules from {len(CATEGORIES)} categories, {dropped} disabled")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: build-ruleset.py emerging.rules.tar.gz sentinel.rules disable.txt", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
