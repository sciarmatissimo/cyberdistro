"""Minimal i18n loader (it/en)."""

from __future__ import annotations

import importlib.resources as res
import yaml

_CACHE: dict[str, dict] = {}


def load(lang: str = "it") -> dict:
    lang = lang if lang in ("it", "en") else "it"
    if lang not in _CACHE:
        text = res.files("cyberdistro_sc.i18n").joinpath(
            f"{lang}.yaml").read_text(encoding="utf-8")
        _CACHE[lang] = yaml.safe_load(text) or {}
    return _CACHE[lang]


def t(key: str, lang: str = "it") -> str:
    return load(lang).get(key, key)
