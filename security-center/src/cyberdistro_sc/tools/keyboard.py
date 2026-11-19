"""Keyboard layout selection — independent of the UI language.

The language edition (it/en) sets only a sensible *default* layout; the user can
pick any layout at runtime from the Security Center. This module lists common
layouts, reads the current one (`setxkbmap -query`) and applies a new one
(`setxkbmap <code>`), and remembers the choice in the user's config so it is
re-applied on the next login (an autostart entry calls `cyberdistro-keyboard
apply`). All command construction is argv lists (no shell).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

# (xkb code, native label). Kept short and widely useful; order is display order.
LAYOUTS = [
    ("us", "English (US)"),
    ("gb", "English (UK)"),
    ("it", "Italiano"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("es", "Español"),
    ("pt", "Português"),
    ("br", "Português (Brasil)"),
    ("ch", "Schweiz / Suisse"),
    ("be", "Belgisch / Belge"),
    ("nl", "Nederlands"),
    ("dk", "Dansk"),
    ("se", "Svenska"),
    ("no", "Norsk"),
    ("fi", "Suomi"),
    ("pl", "Polski"),
    ("cz", "Čeština"),
    ("hu", "Magyar"),
    ("ru", "Русский"),
    ("ua", "Українська"),
    ("gr", "Ελληνικά"),
    ("tr", "Türkçe"),
    ("es", "Español (Latinoamérica)"),  # note: 'latam' below overrides label
    ("latam", "Español (Latinoamérica)"),
    ("jp", "日本語"),
]

CONFIG_DIR = os.path.expanduser("~/.config/cyberdistro")
CONFIG_FILE = os.path.join(CONFIG_DIR, "keyboard")

_VALID = re.compile(r"^[a-z]{2,6}$")


def _run(argv, timeout=10.0):
    if shutil.which(argv[0]) is None:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not installed")
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, -1, "", "timed out")


def layouts() -> list[tuple[str, str]]:
    # de-duplicate by code keeping the first (nicer) label
    seen = {}
    out = []
    for code, label in LAYOUTS:
        if code in seen:
            continue
        seen[code] = label
        out.append((code, label))
    return out


def label_for(code: str) -> str:
    for c, label in layouts():
        if c == code:
            return label
    return code


def is_valid(code: str) -> bool:
    return bool(_VALID.match(code or ""))


def parse_query(text: str) -> str:
    """Extract the layout from `setxkbmap -query` output ('layout:  it,us')."""
    m = re.search(r"^layout:\s*(\S+)", text or "", re.MULTILINE)
    if not m:
        return ""
    return m.group(1).split(",")[0].strip()


def current_layout(run=_run) -> str:
    code = parse_query(run(["setxkbmap", "-query"]).stdout)
    if code:
        return code
    # fall back to the saved choice or the build-time default
    try:
        with open(CONFIG_FILE, encoding="utf-8") as fh:
            saved = fh.read().strip()
            if is_valid(saved):
                return saved
    except OSError:
        pass
    return default_layout()


def default_layout() -> str:
    """Build-time default from /etc/default/keyboard (XKBLAYOUT)."""
    try:
        with open("/etc/default/keyboard", encoding="utf-8") as fh:
            m = re.search(r'^XKBLAYOUT="?([a-z,]+)"?', fh.read(), re.MULTILINE)
            if m:
                return m.group(1).split(",")[0]
    except OSError:
        pass
    return "us"


def plan_set(code: str) -> list[str]:
    return ["setxkbmap", code]


def save_choice(code: str) -> None:
    if not is_valid(code):
        return
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
            fh.write(code + "\n")
    except OSError:
        pass


def apply_layout(code: str, run=_run, persist: bool = True):
    """Apply the layout now (setxkbmap) and remember it for next login."""
    if not is_valid(code):
        raise ValueError(f"invalid layout code: {code!r}")
    res = run(plan_set(code))
    if persist:
        save_choice(code)
    return res
