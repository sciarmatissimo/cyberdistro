"""Tool catalog loader.

Loads the YAML catalog, exposes categories and tools, and enriches each tool
with its live install status (via capabilities.detect_tool). The catalog is the
single source of truth for both the CLI and the GUI.
"""

from __future__ import annotations

import importlib
import importlib.resources as res
from dataclasses import dataclass, field

import yaml

from .authorization import ActivityKind
from .capabilities import detect_tool, ToolStatus


@dataclass
class Tool:
    id: str
    name: str
    executable: str
    activity: ActivityKind
    needs_privilege: bool
    wrapper: str | None
    category_id: str
    docs: dict = field(default_factory=dict)

    def status(self) -> ToolStatus:
        return detect_tool(self.id, self.executable)

    @property
    def has_wrapper(self) -> bool:
        return bool(self.wrapper)

    def load_wrapper(self):
        """Import and return the wrapper module, or None."""
        if not self.wrapper:
            return None
        return importlib.import_module(self.wrapper)


@dataclass
class Category:
    id: str
    title_it: str
    title_en: str
    goal_it: str
    tools: list[Tool] = field(default_factory=list)


class Catalog:
    def __init__(self, categories: list[Category]):
        self.categories = categories
        self._by_id = {t.id: t for c in categories for t in c.tools}

    @classmethod
    def load(cls, path: str | None = None) -> "Catalog":
        if path:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        else:
            text = res.files("cyberdistro_sc.data").joinpath(
                "catalog.yaml").read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        cats = []
        for c in data.get("categories", []):
            tools = []
            for t in c.get("tools", []):
                tools.append(Tool(
                    id=t["id"], name=t["name"], executable=t["executable"],
                    activity=ActivityKind(t.get("activity", "passive")),
                    needs_privilege=bool(t.get("needs_privilege", False)),
                    wrapper=t.get("wrapper"),
                    category_id=c["id"],
                    docs={
                        "what_it_does": t.get("what_it_does_it", ""),
                        "when": t.get("when_it_it", ""),
                        "permissions": t.get("permissions_it", ""),
                    },
                ))
            cats.append(Category(
                id=c["id"], title_it=c["title_it"], title_en=c["title_en"],
                goal_it=c.get("goal_it", ""), tools=tools,
            ))
        return cls(cats)

    def get(self, tool_id: str) -> Tool:
        if tool_id not in self._by_id:
            raise KeyError(f"unknown tool id {tool_id!r}")
        return self._by_id[tool_id]

    def all_tools(self) -> list[Tool]:
        return list(self._by_id.values())
