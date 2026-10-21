"""Safe-by-default authorization gating.

Before any *active* operation the operator must have declared, on the owning
project: the project name, the system owner, and an authorized scope (the set
of targets they are allowed to test). This module decides whether a requested
target falls inside that declared scope.

IMPORTANT (honesty requirement): declaring a scope records the operator's
*stated* intent. It is NOT, and must never be presented as, a legal or
technical guarantee of authorization. The operator remains fully responsible.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum


class ActivityKind(str, Enum):
    """How intrusive an operation is. Drives which confirmations are required."""

    PASSIVE = "passive"      # observe only (e.g. read a capture, hash a file)
    ACTIVE_LIGHT = "active_light"   # touches target but low impact (ping, banner)
    ACTIVE_INTRUSIVE = "active_intrusive"  # scans/probes that may disrupt


class AuthorizationError(Exception):
    """Raised when an operation is not permitted by the declared scope."""


@dataclass
class Authorization:
    """Declared authorization for a project.

    ``scope`` is a list of targets the operator declares they may test. Entries
    may be CIDR networks, single IPs, or hostnames. Hostname matching is exact
    (case-insensitive); IP matching is by network membership.
    """

    project: str
    owner: str
    scope: list[str] = field(default_factory=list)
    note: str = ""

    # ---- scope checks -------------------------------------------------
    def _networks(self) -> list[ipaddress._BaseNetwork]:
        nets = []
        for entry in self.scope:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue  # not an IP/CIDR; handled as hostname
        return nets

    def _hostnames(self) -> set[str]:
        hosts = set()
        for entry in self.scope:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                hosts.add(entry.strip().lower())
        return hosts

    def covers(self, target: str) -> bool:
        """True iff ``target`` is inside the declared scope."""
        t = target.strip().lower()
        if t in self._hostnames():
            return True
        # Try target as IP or CIDR against declared networks.
        try:
            tnet = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for net in self._networks():
            if tnet.version != net.version:
                continue
            # target fully contained in an authorized network
            if tnet.subnet_of(net):
                return True
        return False

    def require(self, target: str, kind: ActivityKind) -> None:
        """Raise unless the target is authorized for this activity kind.

        Passive activity on files/local data does not require a network scope,
        but still requires a named project+owner so the audit trail is complete.
        """
        if not self.project or not self.owner:
            raise AuthorizationError(
                "no project/owner declared — create a project with an owner "
                "and authorized scope before running operations."
            )
        if kind is ActivityKind.PASSIVE:
            return
        if not self.scope:
            raise AuthorizationError(
                "active operation requested but no authorized scope is declared "
                "for this project. Declare the targets you are permitted to test."
            )
        if not self.covers(target):
            raise AuthorizationError(
                f"target {target!r} is OUTSIDE the declared authorized scope "
                f"{self.scope!r}. Refusing. Add it to the scope only if you are "
                f"actually authorized to test it."
            )

    # ---- serialization ------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "project": self.project,
            "owner": self.owner,
            "scope": list(self.scope),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Authorization":
        return cls(
            project=d.get("project", ""),
            owner=d.get("owner", ""),
            scope=list(d.get("scope", [])),
            note=d.get("note", ""),
        )
