"""Minimal i18n loader (it/en).

The default language is resolved once from the environment variable
CYBERDISTRO_LANG (set per-edition at build time, e.g. the English ISO ships
CYBERDISTRO_LANG=en). Falls back to Italian. Callers may still pass an explicit
language to override.
"""

from __future__ import annotations

import importlib.resources as res
import os
import yaml

_CACHE: dict[str, dict] = {}
_DEFAULT: str | None = None


def default_lang() -> str:
    global _DEFAULT
    if _DEFAULT is None:
        v = (os.environ.get("CYBERDISTRO_LANG") or "").strip().lower()[:2]
        _DEFAULT = v if v in ("it", "en") else "it"
    return _DEFAULT


def set_default_lang(lang: str) -> None:
    """Override the process-wide default language (used by the GUI selector)."""
    global _DEFAULT
    _DEFAULT = lang if lang in ("it", "en") else "it"


def load(lang: str | None = None) -> dict:
    lang = lang or default_lang()
    lang = lang if lang in ("it", "en") else "it"
    if lang not in _CACHE:
        text = res.files("cyberdistro_sc.i18n").joinpath(
            f"{lang}.yaml").read_text(encoding="utf-8")
        _CACHE[lang] = yaml.safe_load(text) or {}
    return _CACHE[lang]


def t(key: str, lang: str | None = None) -> str:
    return load(lang).get(key, key)
