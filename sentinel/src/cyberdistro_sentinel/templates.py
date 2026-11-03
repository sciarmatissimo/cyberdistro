"""Hand-written explanation cards (Italian and English).

These always work, with or without the language model. Each card answers the
five questions of the specification: what happened, why it may be dangerous,
what evidence supports it, what to do, whether action is urgent.
Placeholders use only values from ``Incident.facts`` and addresses.
"""

from __future__ import annotations

from datetime import datetime

URGENCY = {
    "it": {"alta": "Sì: agisci adesso.", "media": "Presto: controlla appena puoi.", "bassa": "No: è un'informazione."},
    "en": {"alta": "Yes: act now.", "media": "Soon: check when you can.", "bassa": "No: this is informational."},
}
LEVEL = {
    "it": {"confermato": "Rilevamento confermato dal motore", "sospetto": "Indizio sospetto, da verificare",
           "ipotesi": "Ipotesi dell'assistente"},
    "en": {"confermato": "Confirmed by the detection engine", "sospetto": "Suspicious indicator, needs checking",
           "ipotesi": "Assistant hypothesis"},
}

CARDS = {
    "it": {
        "port_scan": ("Qualcuno sta esplorando le porte di un dispositivo",
                      "Il dispositivo {src} ha provato {ports} porte diverse di {dst} in {window_s} secondi.",
                      "Chi esplora le porte cerca servizi da attaccare: spesso è il primo passo di un attacco.",
                      "Se {src} non è un tuo PC che fa una verifica autorizzata, scollegalo dalla rete o bloccalo da qui."),
        "host_sweep": ("Un dispositivo sta cercando altri dispositivi in rete",
                       "{src} ha contattato {hosts} indirizzi diversi sulla porta {port} in {window_s} secondi.",
                       "Cercare molti dispositivi sulla stessa porta è tipico di malware che si diffonde o di una ricognizione.",
                       "Verifica cosa sta facendo {src}; se non lo riconosci, bloccalo."),
        "brute_force": ("Qualcuno sta provando molte password",
                        "{src} ha aperto {attempts} connessioni al servizio sulla porta {port} di {dst} in {window_s} secondi.",
                        "Tante connessioni di accesso in poco tempo indicano un tentativo di indovinare la password.",
                        "Blocca {src} su questo PC e controlla che le password del servizio siano robuste."),
        "arp_spoof": ("Un dispositivo si spaccia per un altro",
                      "L'indirizzo {ip} prima corrispondeva alla scheda {old_mac}, ora risponde la scheda {new_mac}.",
                      "Se succede al router, il traffico può passare da un intermediario che lo legge o lo modifica (man-in-the-middle).",
                      "Scollegati da questa rete e non inserire password finché non hai capito chi è {new_mac}."),
        "arp_multi_ip": ("Una scheda di rete usa molti indirizzi",
                         "La scheda {mac} ha dichiarato {ip_count} indirizzi IP diversi.",
                         "Può essere un router o un server legittimo, ma anche un dispositivo che intercetta il traffico.",
                         "Controlla di che dispositivo si tratta nella sezione Rete."),
        "new_device": ("Nuovo dispositivo in rete",
                       "È comparso il dispositivo {ip} (scheda {mac}).",
                       "Un dispositivo sconosciuto può essere un ospite, un nuovo apparecchio o un intruso.",
                       "Se non lo riconosci, cambia la password del Wi-Fi del router."),
        "suricata_alert": ("Il motore delle firme ha riconosciuto traffico sospetto",
                           "Suricata ha riconosciuto la firma \"{signature}\" tra {src} e {dst}.",
                           "La firma descrive un comportamento noto: categoria \"{category}\".",
                           "Controlla cosa sta facendo {src}; se è un tuo dispositivo, fai una scansione antivirus."),
        "dns_nxdomain_burst": ("Molte richieste a siti inesistenti",
                               "{src} ha cercato {domains} nomi di dominio inesistenti in {window_s} secondi.",
                               "Alcuni malware generano nomi casuali per trovare il loro server di comando.",
                               "Controlla {src} con un antivirus e chiudi i programmi che non conosci."),
        "dns_tunnel": ("Possibile trasferimento di dati nascosto nel DNS",
                       "{src} ha fatto {queries} richieste DNS insolite (nomi molto lunghi o di tipo TXT) in {window_s} secondi.",
                       "Il DNS può essere usato per far uscire dati o ricevere comandi senza farsi notare.",
                       "Controlla {src}; se non sai spiegarlo, scollegalo dalla rete."),
        "beaconing": ("Un dispositivo contatta lo stesso server a intervalli regolari",
                      "{src} si è collegato {connections} volte a {dst} sulla porta {port}, circa ogni {interval_s} secondi.",
                      "Collegamenti regolari come un orologio sono tipici del malware che \"chiama casa\".",
                      "Verifica quale programma su {src} contatta {dst}; se non lo conosci, blocca {dst}."),
        "exfiltration": ("Molti dati in uscita verso un solo indirizzo",
                         "{src} ha inviato circa {megabytes} MB a {dst} in {window_s} secondi.",
                         "Può essere un backup o un upload legittimo, ma anche una fuga di dati.",
                         "Se non stai caricando file, blocca {dst} e controlla {src}."),
        "lateral_movement": ("Un dispositivo prova ad accedere a molti altri",
                             "{src} ha aperto connessioni di amministrazione verso {hosts} dispositivi in {window_s} secondi.",
                             "È il modo in cui un attaccante si sposta da un dispositivo all'altro.",
                             "Scollega {src} dalla rete e controllalo."),
    },
    "en": {
        "port_scan": ("Someone is probing a device's ports",
                      "Device {src} tried {ports} different ports on {dst} in {window_s} seconds.",
                      "Port probing looks for services to attack; it is often the first step of an attack.",
                      "If {src} is not your own PC running an authorised check, disconnect or block it from here."),
        "host_sweep": ("A device is looking for other devices",
                       "{src} contacted {hosts} different addresses on port {port} in {window_s} seconds.",
                       "Probing many devices on one port is typical of spreading malware or reconnaissance.",
                       "Check what {src} is doing; block it if you do not recognise it."),
        "brute_force": ("Someone is trying many passwords",
                        "{src} opened {attempts} connections to the service on port {port} of {dst} in {window_s} seconds.",
                        "Many login connections in a short time indicate password guessing.",
                        "Block {src} on this PC and make sure the service uses strong passwords."),
        "arp_spoof": ("A device is impersonating another",
                      "Address {ip} used to belong to network card {old_mac}; now card {new_mac} answers.",
                      "If this is the router, traffic may pass through someone who reads or alters it (man-in-the-middle).",
                      "Disconnect from this network and do not type passwords until you know who {new_mac} is."),
        "arp_multi_ip": ("One network card uses many addresses",
                         "Card {mac} announced {ip_count} different IP addresses.",
                         "It may be a legitimate router or server, or a device intercepting traffic.",
                         "Check which device it is in the Network section."),
        "new_device": ("New device on the network",
                       "Device {ip} (card {mac}) appeared.",
                       "An unknown device may be a guest, a new appliance or an intruder.",
                       "If you do not recognise it, change the router's Wi-Fi password."),
        "suricata_alert": ("The signature engine recognised suspicious traffic",
                           "Suricata matched the signature \"{signature}\" between {src} and {dst}.",
                           "The signature describes a known behaviour: category \"{category}\".",
                           "Check what {src} is doing; if it is your device, run an antivirus scan."),
        "dns_nxdomain_burst": ("Many lookups of non-existent sites",
                               "{src} looked up {domains} non-existent domain names in {window_s} seconds.",
                               "Some malware generates random names to find its command server.",
                               "Scan {src} with an antivirus and close programs you do not know."),
        "dns_tunnel": ("Possible data hidden in DNS",
                       "{src} made {queries} unusual DNS queries (very long names or TXT type) in {window_s} seconds.",
                       "DNS can be abused to move data out or receive commands unnoticed.",
                       "Check {src}; if you cannot explain it, disconnect it."),
        "beaconing": ("A device contacts the same server at regular intervals",
                      "{src} connected {connections} times to {dst} on port {port}, about every {interval_s} seconds.",
                      "Clock-like connections are typical of malware \"calling home\".",
                      "Find which program on {src} contacts {dst}; if unknown, block {dst}."),
        "exfiltration": ("A lot of data leaving to one address",
                         "{src} sent about {megabytes} MB to {dst} in {window_s} seconds.",
                         "It may be a legitimate backup or upload, or a data leak.",
                         "If you are not uploading files, block {dst} and check {src}."),
        "lateral_movement": ("A device tries to access many others",
                             "{src} opened administration connections to {hosts} devices in {window_s} seconds.",
                             "This is how an attacker moves from one device to another.",
                             "Disconnect {src} and check it."),
    },
}


class _Safe(dict):
    def __missing__(self, k):
        return "?"


def card(inc: dict, lang: str = "it") -> dict:
    lang = lang if lang in CARDS else "it"
    tpl = CARDS[lang].get(inc["rule"])
    vals = _Safe({**inc.get("facts", {}), "src": inc.get("src") or "?", "dst": inc.get("dst") or "?"})
    if tpl is None:
        tpl = ("Evento di sicurezza" if lang == "it" else "Security event", inc["rule"], "", "")
    title, what, why, todo = (t.format_map(vals) for t in tpl)
    when = datetime.fromtimestamp(inc["last_ts"]).strftime("%d/%m %H:%M:%S")
    ev_label = "Prove" if lang == "it" else "Evidence"
    evidence = [f"{len(inc.get('evidence', []))} record ({', '.join(sorted({e.split(':')[0] for e in inc.get('evidence', [])}))})",
                f"{'ultimo' if lang == 'it' else 'last'}: {when}",
                f"{'occorrenze' if lang == 'it' else 'occurrences'}: {inc.get('count', 1)}"]
    return {"title": title, "what": what, "why": why, "evidence": evidence, "evidence_label": ev_label,
            "todo": todo, "urgency": URGENCY[lang][inc["severity"]], "level": LEVEL[lang][inc["level"]],
            "severity": inc["severity"]}
