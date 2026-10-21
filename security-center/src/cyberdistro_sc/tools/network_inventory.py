"""Guided network inventory wrapper around Nmap.

Scope: authorized asset inventory and service discovery. This wrapper builds a
conservative, non-destructive Nmap invocation and parses the real XML output
into a structured inventory. It is deliberately limited to discovery/inventory
profiles; it does not wrap exploitation features.

Safety:
  * Active operation → requires an Authorization whose scope covers the target.
  * Intensity is capped (timing template bounded; no aggressive NSE by default).
  * The exact command is always recorded.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..core.authorization import Authorization, ActivityKind
from ..core.runner import CommandPlan, CommandResult, CommandRunner

TOOL_ID = "nmap-inventory"

# Discovery/inventory profiles only. Values map to safe, well-understood flags.
PROFILES = {
    "discovery": {
        "desc_it": "Scopri quali host sono attivi (ping scan, nessuna porta).",
        "args": ["-sn"],
        "activity": ActivityKind.ACTIVE_LIGHT,
    },
    "quick-ports": {
        "desc_it": "Porte più comuni sugli host attivi (top 100).",
        "args": ["-sT", "--top-ports", "100", "-T3"],
        "activity": ActivityKind.ACTIVE_LIGHT,
    },
    "service-inventory": {
        "desc_it": "Servizi e versioni sulle porte comuni (più lento).",
        "args": ["-sT", "-sV", "--top-ports", "200", "-T3"],
        "activity": ActivityKind.ACTIVE_INTRUSIVE,
    },
}


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class HostInventory:
    address: str
    hostname: str = ""
    state: str = "unknown"
    services: list[Service] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": self.address, "hostname": self.hostname,
            "state": self.state,
            "services": [s.__dict__ for s in self.services],
        }


def explain() -> dict:
    return {
        "what_it_does": "Elenca host attivi e servizi aperti in un intervallo "
                        "autorizzato, per costruire un inventario.",
        "when": "Quando devi sapere quali dispositivi/servizi esistono in una "
                "rete di cui sei responsabile.",
        "permissions": "Progetto con proprietario e ambito autorizzato. Alcune "
                       "modalità avanzate di Nmap richiedono root (qui non usate).",
        "profiles": {k: v["desc_it"] for k, v in PROFILES.items()},
        "note": "Operazione ATTIVA: tocca i sistemi di destinazione.",
    }


def plan(target: str, profile: str = "discovery",
         extra_args: list[str] | None = None) -> CommandPlan:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; "
                         f"choose from {', '.join(PROFILES)}")
    spec = PROFILES[profile]
    argv = ["nmap", *spec["args"], "-oX", "-", target]
    if extra_args:
        # Expert mode may append flags; they are shown in the preview and logged.
        argv[1:1] = list(extra_args)
    return CommandPlan(
        tool_id=TOOL_ID, argv=argv,
        description=spec["desc_it"],
        needs_privilege=False,
        activity=spec["activity"].value,
    )


def run(target: str, auth: Authorization, profile: str = "discovery",
        runner: CommandRunner | None = None,
        extra_args: list[str] | None = None,
        timeout: float = 600.0) -> tuple[CommandResult, list[HostInventory]]:
    """Authorize, run, and parse. Raises AuthorizationError if out of scope."""
    spec = PROFILES[profile]
    auth.require(target, spec["activity"])      # safe-by-default gate
    p = plan(target, profile, extra_args)
    runner = runner or CommandRunner(default_timeout=timeout)
    result = runner.run(p, timeout=timeout)
    hosts = parse_xml(result.stdout) if result.stdout.strip() else []
    return result, hosts


def parse_xml(xml_text: str) -> list[HostInventory]:
    """Parse Nmap XML into structured inventory. Pure function → unit-testable."""
    hosts: list[HostInventory] = []
    root = ET.fromstring(xml_text)
    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state") if status is not None else "unknown"
        addr = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        hostname = ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        inv = HostInventory(address=addr, hostname=hostname, state=state)
        for port in h.findall("ports/port"):
            pstate = port.find("state")
            svc = port.find("service")
            inv.services.append(Service(
                port=int(port.get("portid", "0")),
                protocol=port.get("protocol", ""),
                state=pstate.get("state") if pstate is not None else "",
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
            ))
        hosts.append(inv)
    return hosts
