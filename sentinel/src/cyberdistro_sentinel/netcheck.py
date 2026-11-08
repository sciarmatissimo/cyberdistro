"""Network safety checks for the connection this PC is on (2c):
Wi-Fi protection, "evil-twin" clone access points, and DNS hijacking.

The functions here are pure: they take the text output of ordinary commands
(``nmcli``, a DNS lookup) and return findings. The Security Center runs the
commands in the user session and passes the output in, so the logic is testable
offline and never needs the network itself.

A finding is ``{"level": ok|info|warn|danger, "title": str, "detail": str}``.
"""

from __future__ import annotations

import ipaddress

OK, INFO, WARN, DANGER = "ok", "info", "warn", "danger"


def _split_terse(line: str) -> list[str]:
    """Split one nmcli --terse line on unescaped ':' (BSSID colons are '\\:')."""
    out, cur, i = [], [], 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if c == ":":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def _weak(sec: str) -> bool:
    s = sec.upper()
    return "WEP" in s or ("WPA1" in s and "WPA2" not in s and "WPA3" not in s)


def wifi_findings(nmcli_wifi: str) -> list[dict]:
    """From ``nmcli -t -f IN-USE,SSID,SECURITY,CHAN,SIGNAL,BSSID dev wifi``.

    Reports the protection of the network this PC is on, and flags an SSID that
    is advertised with two different kinds of protection (a classic evil-twin
    sign). Several access points with the SAME protection is normal (mesh), so
    that is only informational."""
    rows = []
    for line in nmcli_wifi.splitlines():
        f = _split_terse(line)
        if len(f) < 6:
            continue
        rows.append({"inuse": f[0].strip() == "*", "ssid": f[1], "sec": (f[2] or "").strip(),
                     "signal": f[4], "bssid": f[-1]})
    out: list[dict] = []
    cur = next((r for r in rows if r["inuse"]), None)
    if cur:
        sec = cur["sec"]
        if not sec or sec == "--":
            out.append({"level": DANGER, "title": f"La rete «{cur['ssid']}» è aperta",
                        "detail": "Senza password, chiunque nel raggio può leggere il traffico non cifrato e "
                                  "unirsi alla rete. Usala solo con Tor o una VPN, e mai per cose riservate."})
        elif _weak(cur["sec"]):
            out.append({"level": WARN, "title": f"La rete «{cur['ssid']}» usa una protezione debole ({sec})",
                        "detail": "WEP e WPA1 si violano in pochi minuti. Se è il tuo router, passa a WPA2 o WPA3."})
        else:
            out.append({"level": OK, "title": f"La rete «{cur['ssid']}» è protetta ({sec})", "detail": ""})
    # evil twin: same SSID, different security kinds
    by_ssid: dict[str, set[str]] = {}
    for r in rows:
        if r["ssid"]:
            by_ssid.setdefault(r["ssid"], set()).add("aperta" if not r["sec"] or r["sec"] == "--" else r["sec"])
    for ssid, secs in by_ssid.items():
        if len(secs) > 1:
            out.append({"level": DANGER, "title": f"Due reti diverse si chiamano «{ssid}»",
                        "detail": "Lo stesso nome compare con protezioni diverse (" + ", ".join(sorted(secs))
                                  + "). Può essere una «rete gemella» creata per intercettare chi si collega. "
                                  "Verifica di connetterti a quella giusta; nel dubbio, usa il cavo o i dati del telefono."})
    return out


def dns_findings(random_name: str, answers: list[str], control_answers: list[str] | None = None) -> list[dict]:
    """A guaranteed-nonexistent name must come back empty (NXDOMAIN). If the
    network's resolver returns an address for it, it is hijacking DNS
    (captive portal, ad/redirect injection). ``control_answers``, if given, is the
    same lookup done against a public resolver — used only to confirm."""
    real = [a for a in answers if _is_ip(a)]
    if not real:
        return [{"level": OK, "title": "Il DNS della rete risponde correttamente",
                 "detail": "Un nome inesistente viene segnalato come tale, come dovrebbe."}]
    if control_answers is not None and [a for a in control_answers if _is_ip(a)]:
        # even a public resolver returned something: it's a wildcard TLD, not hijacking
        return [{"level": INFO, "title": "Nome di prova non adatto",
                 "detail": "Il controllo non è conclusivo su questa rete."}]
    return [{"level": DANGER, "title": "Il DNS della rete reindirizza i nomi inesistenti",
             "detail": f"Ho chiesto un nome che non esiste ({random_name}) e il router ha risposto con un "
                       f"indirizzo ({', '.join(real[:3])}). Significa che il DNS della rete riscrive le risposte: "
                       "può servire a mostrare pubblicità o a dirottarti su siti falsi. Usa un DNS cifrato "
                       "(DNS-over-HTTPS) o Tor."}]


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def worst(findings: list[dict]) -> str:
    rank = {OK: 0, INFO: 1, WARN: 2, DANGER: 3}
    return max((f["level"] for f in findings), key=lambda l: rank.get(l, 0)) if findings else OK
