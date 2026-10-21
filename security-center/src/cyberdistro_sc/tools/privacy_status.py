"""Privacy / Tor status inspection.

Reports, truthfully, the current privacy posture:
  * whether a Tor process / SOCKS port is present,
  * which privacy profile the kill-switch indicates,
  * configured DNS resolvers (to flag likely DNS-leak conditions),
  * whether the nftables kill-switch ruleset is loaded.

This module only INSPECTS state. Changing the privacy profile is a privileged,
explicit action handled by the privacy CLI (privacy/bin), never silently here.
It never claims "you are anonymous"; it reports observable facts and known limits.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field

TOR_SOCKS_PORTS = (9050, 9150)   # tor daemon, Tor Browser


@dataclass
class PrivacyStatus:
    tor_installed: bool
    tor_socks_open: bool
    socks_port: int | None
    killswitch_loaded: bool
    dns_resolvers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tor_installed": self.tor_installed,
            "tor_socks_open": self.tor_socks_open,
            "socks_port": self.socks_port,
            "killswitch_loaded": self.killswitch_loaded,
            "dns_resolvers": list(self.dns_resolvers),
            "warnings": list(self.warnings),
            "limits": list(self.limits),
        }


_ANON_LIMITS = [
    "Tor non protegge se accedi ad account personali.",
    "Tor non impedisce il fingerprinting se alteri il browser.",
    "Tor non protegge da tutti gli attacchi di correlazione del traffico.",
    "File scaricati e aperti fuori dall'ambiente protetto possono deanonimizzarti.",
    "Malware o compromissione del dispositivo annullano l'anonimato.",
    "Questo stato riporta fatti osservabili, non una garanzia di anonimato.",
]


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _read_dns_resolvers() -> list[str]:
    resolvers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])
    except OSError:
        pass
    return resolvers


def _killswitch_loaded() -> bool:
    """True if the CyberDistro kill-switch table is present in nftables."""
    if shutil.which("nft") is None:
        return False
    try:
        p = subprocess.run(["nft", "list", "tables"], capture_output=True,
                           text=True, timeout=5, check=False)
        return "cyberdistro_killswitch" in p.stdout
    except Exception:
        return False


def status() -> PrivacyStatus:
    tor_installed = shutil.which("tor") is not None or os.path.isdir("/opt/tor-browser")
    socks_port = None
    for port in TOR_SOCKS_PORTS:
        if _port_open(port):
            socks_port = port
            break
    ks = _killswitch_loaded()
    resolvers = _read_dns_resolvers()
    warnings: list[str] = []

    # DNS-leak heuristic: when the kill-switch (Tor mode) is loaded, resolvers
    # should be the local Tor DNS (127.0.0.1) only. A public resolver then is a
    # red flag worth surfacing.
    if ks:
        non_local = [r for r in resolvers if not r.startswith("127.")]
        if non_local:
            warnings.append(
                f"Kill-switch attivo ma risolutori DNS non locali presenti "
                f"({', '.join(non_local)}): possibile DNS leak. Verifica la configurazione."
            )
    if socks_port is None and ks:
        warnings.append(
            "Kill-switch attivo ma nessuna porta SOCKS Tor rilevata: la rete "
            "potrebbe essere bloccata (fail-closed) finché Tor non è pronto."
        )

    return PrivacyStatus(
        tor_installed=tor_installed,
        tor_socks_open=socks_port is not None,
        socks_port=socks_port,
        killswitch_loaded=ks,
        dns_resolvers=resolvers,
        warnings=warnings,
        limits=list(_ANON_LIMITS),
    )
