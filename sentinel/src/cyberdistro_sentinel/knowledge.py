"""Hand-written security knowledge used to explain what an examination found.

Open TCP ports are mapped to: what the service is, how risky an open port is on
a home/office network, and what a non-expert can do. The text is ours, never
taken from the network, so it can be shown and given to the model safely.
"""

from __future__ import annotations

import re

HIGH, MEDIUM, LOW = "alta", "media", "bassa"

# port: (it name, en name, risk, it advice, en advice)
PORTS = {
    21: ("FTP (scambio file)", "FTP (file transfer)", HIGH,
         "Le password viaggiano in chiaro. Disattiva l'FTP dal pannello del dispositivo o usa SFTP.",
         "Passwords travel in clear text. Disable FTP in the device settings or use SFTP."),
    22: ("SSH (accesso remoto)", "SSH (remote access)", MEDIUM,
         "Normale su server e router; usa password robuste o chiavi, e disattivalo se non lo usi.",
         "Normal on servers and routers; use strong passwords or keys, and disable it if unused."),
    23: ("Telnet (accesso remoto non cifrato)", "Telnet (unencrypted remote access)", HIGH,
         "Servizio vecchio e non cifrato, molto usato dai malware per prendere il controllo di router e telecamere. Disattivalo e cambia la password.",
         "Old unencrypted service, widely abused by malware to take over routers and cameras. Disable it and change the password."),
    25: ("SMTP (posta)", "SMTP (mail)", MEDIUM,
         "Insolito su un dispositivo di casa: verifica che sia un server di posta voluto.",
         "Unusual on a home device: make sure it is an intended mail server."),
    53: ("DNS", "DNS", LOW, "Normale sul router.", "Normal on the router."),
    80: ("pagina web (HTTP, non cifrata)", "web page (HTTP, unencrypted)", LOW,
         "Spesso è il pannello di configurazione: assicurati che abbia una password non predefinita.",
         "Often the configuration panel: make sure it does not use the default password."),
    110: ("POP3 (posta non cifrata)", "POP3 (unencrypted mail)", MEDIUM,
          "Le password viaggiano in chiaro: preferisci la versione cifrata.", "Passwords travel in clear text: prefer the encrypted version."),
    135: ("Windows RPC", "Windows RPC", MEDIUM,
          "Tipico dei PC Windows; non deve essere raggiungibile da internet.", "Typical of Windows PCs; must not be reachable from the internet."),
    139: ("condivisione file Windows (NetBIOS)", "Windows file sharing (NetBIOS)", MEDIUM,
          "Condivisione file vecchio stile: disattivala se non condividi cartelle.", "Old-style file sharing: disable it if you do not share folders."),
    143: ("IMAP (posta non cifrata)", "IMAP (unencrypted mail)", MEDIUM,
          "Le password viaggiano in chiaro: preferisci la versione cifrata.", "Passwords travel in clear text: prefer the encrypted version."),
    443: ("pagina web cifrata (HTTPS)", "encrypted web page (HTTPS)", LOW,
          "Normale; se è un pannello di configurazione, usa una password robusta.", "Normal; if it is a configuration panel, use a strong password."),
    445: ("condivisione file Windows (SMB)", "Windows file sharing (SMB)", MEDIUM,
          "Usato da ransomware per diffondersi. Aggiorna il sistema e disattiva la condivisione se non serve.",
          "Used by ransomware to spread. Keep the system updated and disable sharing if not needed."),
    554: ("flusso video (RTSP, telecamere)", "video stream (RTSP, cameras)", MEDIUM,
          "Tipico delle telecamere: controlla che il video richieda una password.", "Typical of cameras: check that the video requires a password."),
    631: ("stampa di rete (IPP)", "network printing (IPP)", LOW, "Normale per una stampante.", "Normal for a printer."),
    1883: ("MQTT (dispositivi smart)", "MQTT (smart devices)", MEDIUM,
           "Spesso senza password: verifica le impostazioni del dispositivo.", "Often without a password: check the device settings."),
    1900: ("UPnP", "UPnP", MEDIUM,
           "Permette ai dispositivi di aprire porte sul router da soli: disattivalo sul router se non serve.",
           "Lets devices open router ports on their own: disable it on the router if not needed."),
    3306: ("database MySQL", "MySQL database", HIGH,
           "Un database non dovrebbe essere raggiungibile da altri dispositivi: limita l'accesso.", "A database should not be reachable from other devices: restrict access."),
    3389: ("Desktop remoto Windows (RDP)", "Windows Remote Desktop (RDP)", HIGH,
           "Bersaglio frequente di attacchi alle password. Disattivalo se non lo usi o proteggilo con una password robusta.",
           "Frequent target of password attacks. Disable it if unused or protect it with a strong password."),
    5000: ("servizio web / UPnP", "web service / UPnP", LOW, "Spesso è un'interfaccia del dispositivo.", "Often a device interface."),
    5900: ("VNC (controllo remoto dello schermo)", "VNC (remote screen control)", HIGH,
           "Permette di vedere e comandare lo schermo: deve avere una password robusta o essere disattivato.",
           "Lets someone see and control the screen: it needs a strong password or should be disabled."),
    8080: ("pagina web alternativa", "alternative web page", LOW,
           "Spesso un pannello di amministrazione: controlla la password.", "Often an admin panel: check its password."),
    8443: ("pagina web cifrata alternativa", "alternative encrypted web page", LOW,
           "Spesso un pannello di amministrazione: controlla la password.", "Often an admin panel: check its password."),
    9100: ("stampa diretta (JetDirect)", "raw printing (JetDirect)", LOW, "Normale per una stampante.", "Normal for a printer."),
}

OPEN_RE = re.compile(r"^(\d+)/tcp\s+open\b")


def parse_nmap_open(out: str) -> list[int]:
    """Open TCP ports from normal nmap output."""
    ports = []
    for line in out.splitlines():
        m = OPEN_RE.match(line.strip())
        if m:
            ports.append(int(m.group(1)))
    return sorted(set(ports))


def describe_port(port: int, lang: str = "it") -> dict:
    p = PORTS.get(port)
    if not p:
        return {"port": port, "name": "servizio non comune" if lang == "it" else "uncommon service",
                "risk": MEDIUM,
                "advice": ("Servizio che non conosco: se non sai a cosa serve, controlla le impostazioni del dispositivo."
                           if lang == "it" else "A service I do not know: if you do not know what it is for, check the device settings.")}
    return {"port": port, "name": p[0] if lang == "it" else p[1], "risk": p[2], "advice": p[3] if lang == "it" else p[4]}


def summarize_ports(ports: list[int], lang: str = "it") -> str:
    """One short line per open port, highest risk first."""
    if not ports:
        return "Nessuna delle porte comuni è aperta." if lang == "it" else "None of the common ports is open."
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    items = sorted((describe_port(p, lang) for p in ports), key=lambda d: (order[d["risk"]], d["port"]))
    risk_word = {"it": {HIGH: "rischio alto", MEDIUM: "rischio medio", LOW: "rischio basso"},
                 "en": {HIGH: "high risk", MEDIUM: "medium risk", LOW: "low risk"}}[lang if lang == "en" else "it"]
    return "\n".join(f"Porta {d['port']}: {d['name']} — {risk_word[d['risk']]}. {d['advice']}" if lang == "it"
                     else f"Port {d['port']}: {d['name']} — {risk_word[d['risk']]}. {d['advice']}" for d in items)


def ports_from_result(result: str) -> list[int]:
    """Ports stored in an action result ("porte aperte: 22,80" / "nessuna porta comune aperta")."""
    m = re.search(r"porte aperte:\s*([\d,\s]+)", result or "")
    return [int(x) for x in re.findall(r"\d+", m.group(1))] if m else []
