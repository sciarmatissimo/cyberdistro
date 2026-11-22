"""Local AI assistant — answers the user's questions, including help while
using the Network Monitor (bridge) mode.

Principles, consistent with CyberDistro:
  * **Local only.** The assistant talks to a model running on THIS machine
    (llama.cpp's OpenAI-compatible server, or Ollama) — never a cloud service.
    No data leaves the computer, no account, no API key.
  * **Useful without a model.** The lean PC edition does not bundle a multi-GB
    model, so when no local model is reachable the assistant still answers from
    a built-in knowledge base about the monitor/bridge and the tools, and tells
    the user how to enable the full local AI (bundled in the Sentinel edition).
  * **Honest & testable.** The HTTP call is injectable; the offline knowledge
    base is a set of pure functions covered by unit tests. The assistant is told
    (system prompt) to stay factual and to answer in the UI language.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request

from ..i18n import default_lang
from . import localmodel

# Candidate local endpoints, tried in order. Override with CYBERDISTRO_AI_URL
# (an OpenAI-compatible /v1/chat/completions URL) + CYBERDISTRO_AI_MODEL.
ENDPOINTS = [
    ("openai", "http://127.0.0.1:8080/v1/chat/completions"),   # llama.cpp server
    ("openai", "http://127.0.0.1:8081/v1/chat/completions"),   # Sentinel model server
    ("ollama", "http://127.0.0.1:11434/api/chat"),             # Ollama
]

SYSTEM_PROMPT = {
    "it": ("Sei l'assistente di CyberDistro, una distribuzione Linux per la "
           "sicurezza informatica con interfaccia semplice. Aiuti anche utenti "
           "non esperti. Rispondi in italiano, in modo breve e concreto. Non "
           "inventare: se non sai, dillo. Ricorda che gli strumenti vanno usati "
           "solo su reti e sistemi propri o autorizzati. In «Monitor di rete» il "
           "PC fa da ponte trasparente e osserva il traffico in modo passivo: i "
           "contenuti cifrati (HTTPS) non sono leggibili, si vedono soprattutto "
           "indirizzi, nomi dei siti e metadati."),
    "en": ("You are the CyberDistro assistant, a Linux security distribution "
           "with a simple interface. You help non-expert users too. Answer in "
           "English, briefly and concretely. Do not make things up: if you "
           "don't know, say so. Remember tools must be used only on your own or "
           "authorized networks and systems. In 'Network monitor' the PC is a "
           "transparent bridge observing traffic passively: encrypted (HTTPS) "
           "contents are not readable; you mainly see addresses, site names and "
           "metadata."),
}


# --------------------------------------------------------------- transport
def _http_post(url: str, payload: dict, timeout: float = 60.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (localhost)
        return json.loads(resp.read().decode("utf-8", "replace"))


def _probe(url: str, timeout: float = 1.5) -> bool:
    base = re.sub(r"/v1/.*$|/api/.*$", "", url)
    for path in ("/health", "/v1/models", "/api/tags", "/"):
        try:
            with urllib.request.urlopen(base + path, timeout=timeout) as r:  # noqa: S310
                if r.status < 500:
                    return True
        except Exception:
            continue
    return False


def endpoints() -> list[tuple[str, str]]:
    url = os.environ.get("CYBERDISTRO_AI_URL")
    if url:
        kind = "ollama" if "/api/" in url else "openai"
        return [(kind, url)]
    return list(ENDPOINTS)


def available(prober=_probe) -> tuple[bool, str, str]:
    """Return (ok, kind, url) for the first reachable local model server."""
    for kind, url in endpoints():
        if prober(url):
            return True, kind, url
    return False, "", ""


# ----------------------------------------------------------- request build
def build_messages(question: str, context: str = "") -> list[dict]:
    sys = SYSTEM_PROMPT.get(default_lang(), SYSTEM_PROMPT["it"])
    msgs = [{"role": "system", "content": sys}]
    if context.strip():
        tag = ("Contesto osservato adesso:" if default_lang() == "it"
               else "Context observed right now:")
        msgs.append({"role": "system", "content": f"{tag}\n{context.strip()}"})
    msgs.append({"role": "user", "content": question.strip()})
    return msgs


def build_payload(kind: str, question: str, context: str = "",
                  model: str | None = None) -> dict:
    model = model or os.environ.get("CYBERDISTRO_AI_MODEL", "local")
    messages = build_messages(question, context)
    if kind == "ollama":
        return {"model": model, "messages": messages, "stream": False,
                "options": {"temperature": 0.2}}
    return {"model": model, "messages": messages, "stream": False,
            "temperature": 0.2}


def parse_response(kind: str, resp: dict) -> str:
    try:
        if kind == "ollama":
            return (resp.get("message", {}) or {}).get("content", "").strip()
        return resp["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError):
        return ""


def ask_model(question: str, context: str, kind: str, url: str,
              transport=_http_post) -> str:
    payload = build_payload(kind, question, context)
    resp = transport(url, payload)
    return parse_response(kind, resp)


# --------------------------------------------------- offline knowledge base
def summarize_context(context: str) -> str:
    return context.strip()


_FAQ = [
    (r"\b(https|cifrat|encrypt|leggere i contenut|contents)",
     ("In modalità Monitor vedi gli indirizzi, i nomi dei siti (dal DNS o "
      "dall'handshake TLS) e i metadati, ma NON i contenuti: il traffico HTTPS "
      "è cifrato. Per leggere i contenuti servirebbe un'intercettazione TLS "
      "attiva, che non è prevista (e richiederebbe di installare un certificato "
      "su ogni dispositivo).",
      "In Monitor mode you see addresses, site names (from DNS or the TLS "
      "handshake) and metadata, but NOT the contents: HTTPS traffic is "
      "encrypted. Reading contents would need active TLS interception, which is "
      "not provided (and would require installing a certificate on every "
      "device).")),
    (r"\b(bridge|ponte|due schede|trasparent|transparent)",
     ("Il «bridge trasparente» unisce le due schede di rete in un ponte senza "
      "indirizzo IP: il PC diventa invisibile e, messo tra il router e il resto "
      "della rete, lascia passare tutto il traffico e te lo mostra. È solo "
      "osservazione: non modifica nulla.",
      "The 'transparent bridge' joins the two network cards into a bridge with "
      "no IP address: the PC becomes invisible and, placed between the router "
      "and the rest of the network, lets all traffic through and shows it to "
      "you. It is observation only: it changes nothing.")),
    (r"\b(device|dispositiv|chi c'è|who is|mac)",
     ("Ogni tile è un dispositivo visto sulla rete, identificato dal suo "
      "indirizzo IP e MAC; sotto trovi quanti pacchetti ha generato e quanti "
      "siti ha contattato. Un MAC «casuale» significa che il dispositivo "
      "nasconde il produttore (privacy).",
      "Each tile is a device seen on the network, identified by its IP and MAC "
      "address; below it you see how many packets it generated and how many "
      "sites it contacted. A 'random' MAC means the device hides its vendor "
      "(privacy).")),
    (r"\b(sit[oi]|site\b|dns\b|domin|domain)",
     ("I «siti contattati» sono i nomi di dominio che i dispositivi hanno "
      "cercato (DNS) o aperto in HTTPS (campo SNI). Un sito contattato spesso "
      "non significa per forza che l'utente lo stia visitando: molte app e "
      "servizi contattano domini in background.",
      "The 'sites contacted' are the domain names devices looked up (DNS) or "
      "opened over HTTPS (SNI field). A frequently contacted site does not "
      "necessarily mean the user is visiting it: many apps and services contact "
      "domains in the background.")),
    (r"\b(tor\b|anonim|anonym|privacy)",
     ("Per navigare in modo anonimo usa la sezione Privacy e Tor Browser. La "
      "modalità «Anonimato Tor» attiva un kill-switch: se Tor cade, non esce "
      "traffico. L'anonimato non è mai assoluto: attenzione ad account "
      "personali, fingerprinting e metadati.",
      "To browse anonymously use the Privacy section and Tor Browser. The 'Tor "
      "anonymity' mode enables a kill-switch: if Tor drops, no traffic leaves. "
      "Anonymity is never absolute: beware of personal accounts, fingerprinting "
      "and metadata.")),
    (r"\b(autorizz|legal|permess|allowed|authori[sz])",
     ("Usa il monitoraggio solo sulla tua rete o su una rete per cui hai "
      "l'autorizzazione. Intercettare il traffico di una rete altrui senza "
      "consenso è illegale.",
      "Use monitoring only on your own network or one you are authorized to "
      "monitor. Intercepting someone else's network traffic without consent is "
      "illegal.")),
    (r"\b(spia|spiare|spiat|controlla la mia rete|intrus|qualcuno (è|e') |"
     r"spy|spying|snoop|someone on my network|intrud)\b",
     ("Per capire se c'è qualcosa di sospetto sulla tua rete: apri «Esplora» per "
      "vedere tutti i dispositivi collegati (se ne riconosci qualcuno di estraneo, "
      "indaga), e usa il «Monitor di rete» per vedere con chi comunicano e quali "
      "siti contattano. Attenzione: vedere traffico cifrato è normale; un "
      "dispositivo sconosciuto o molto traffico verso indirizzi che non riconosci "
      "sono i segnali su cui concentrarsi.",
      "To tell whether something suspicious is on your network: open 'Explore' to "
      "see every connected device (investigate any you don't recognize), and use "
      "the 'Network Monitor' to see who they talk to and which sites they contact. "
      "Note: encrypted traffic is normal; an unknown device, or lots of traffic to "
      "addresses you don't recognize, are the signals to focus on.")),
    (r"\b(come (inizio|comincio|uso|funziona)|da dove|first|get started|how do i|how to use)",
     ("Se non sai da dove iniziare: «Esplora» ti mostra chi c'è sulla tua rete in "
      "modo visuale; «Monitor di rete» (serve un PC con due schede) mostra il "
      "traffico; «Privacy» apre Tor Browser per navigare anonimo; «Forense» e "
      "«Debug» installano strumenti quando ti servono. Ogni sezione spiega cosa fa "
      "prima di agire.",
      "If you don't know where to start: 'Explore' shows who is on your network "
      "visually; 'Network Monitor' (needs a PC with two network cards) shows the "
      "traffic; 'Privacy' opens Tor Browser for anonymous browsing; 'Forensics' and "
      "'Debugging' install tools when you need them. Each section explains what it "
      "does before acting.")),
    (r"\b(nmap|scansion|scan\b|porte|ports)",
     ("Una scansione (es. Nmap) controlla quali dispositivi sono attivi e quali "
      "«porte» (servizi) hanno aperte. In «Esplora» la scansione è limitata alla "
      "tua rete e serve solo a elencare i dispositivi; per un inventario dettagliato "
      "usa la modalità Professionista con un progetto dall'ambito autorizzato.",
      "A scan (e.g. Nmap) checks which devices are up and which 'ports' (services) "
      "they have open. In 'Explore' the scan is limited to your network and only "
      "lists devices; for a detailed inventory use Professional mode with a project "
      "that has an authorized scope.")),
    (r"\b(wireshark|cattur|pacchett|capture|packet)",
     ("Wireshark registra i pacchetti che passano e te li mostra. Nel Monitor di "
      "rete lo apriamo già filtrato sulle cose comprensibili (richieste DNS, siti "
      "in HTTPS, richieste HTTP). Ricorda che i contenuti cifrati non sono leggibili: "
      "vedi indirizzi, nomi dei siti e tempi, non il contenuto delle pagine.",
      "Wireshark records the packets that pass and shows them to you. In the Network "
      "Monitor we open it pre-filtered to the understandable things (DNS lookups, "
      "HTTPS sites, HTTP requests). Remember encrypted contents are not readable: you "
      "see addresses, site names and timing, not the content of pages.")),
    (r"\b(forens|recuper|file cancellat|recover|deleted|disco|disk|immagine)",
     ("Per la forense: nella sezione «Forense e acquisizione» puoi fare una copia "
      "esatta di un disco (Guymager), analizzarla (Autopsy), recuperare file "
      "cancellati (PhotoRec/foremost) e ricostruire cosa è successo nel tempo "
      "(Plaso). Regola d'oro: lavora sempre su una copia, mai sull'originale.",
      "For forensics: in the 'Forensics & acquisition' section you can make an exact "
      "copy of a disk (Guymager), analyze it (Autopsy), recover deleted files "
      "(PhotoRec/foremost) and reconstruct what happened over time (Plaso). Golden "
      "rule: always work on a copy, never on the original.")),
    (r"\b(tastier|layout|keyboard)",
     ("Puoi scegliere il layout della tastiera dal menu «Tastiera» in basso a "
      "sinistra: è indipendente dalla lingua dell'interfaccia e si applica subito.",
      "You can choose the keyboard layout from the 'Keyboard' menu at the bottom "
      "left: it is independent of the interface language and applies immediately.")),
    (r"\b(persisten|salv|mantien|persist|save my work|keep)",
     ("In modalità Live senza persistenza tutto sparisce al riavvio. Attivando la "
      "persistenza cifrata (LUKS2) le tue configurazioni, i progetti e gli strumenti "
      "installati restano, protetti da una passphrase. Il disco interno non viene "
      "mai toccato automaticamente.",
      "In Live mode without persistence everything is gone at reboot. By enabling "
      "encrypted persistence (LUKS2) your settings, projects and installed tools "
      "remain, protected by a passphrase. The internal disk is never touched "
      "automatically.")),
]


def offline_answer(question: str, context: str = "") -> str:
    it = default_lang() != "en"
    q = (question or "").lower()
    hits = []
    for pat, (ans_it, ans_en) in _FAQ:
        if re.search(pat, q):
            hits.append(ans_it if it else ans_en)
    parts = []
    if hits:
        # de-duplicate while preserving order, keep the two most relevant
        seen = set()
        for h in hits:
            if h not in seen:
                seen.add(h)
                parts.append(h)
            if len(parts) >= 2:
                break
    else:
        parts.append(
            "Non ho un modello AI attivo per rispondere liberamente, ma posso "
            "orientarti. Posso spiegarti: il Monitor di rete e il bridge "
            "trasparente, chi c'è sulla tua rete (Esplora), perché i contenuti "
            "HTTPS non sono leggibili, come navigare anonimo con Tor, la forense e "
            "il recupero file, il reverse engineering, la tastiera e la "
            "persistenza. Prova a chiedere con una di queste parole." if it else
            "I don't have an active AI model to answer freely, but I can point you "
            "the right way. I can explain: the Network Monitor and transparent "
            "bridge, who is on your network (Explore), why HTTPS contents aren't "
            "readable, how to browse anonymously with Tor, forensics and file "
            "recovery, reverse engineering, the keyboard and persistence. Try "
            "asking with one of these words.")
    if context.strip():
        parts.append((("Riguardo a ciò che stai osservando adesso — "
                       if it else "About what you are observing now — ")
                      + summarize_context(context)))
    note = ("\n\n(Assistente in modalità base: nessun modello AI locale attivo. "
            "Con un modello locale avviato rispondo anche a domande libere.)" if it else
            "\n\n(Assistant in basic mode: no local AI model running. With a "
            "local model started I also answer free-form questions.)")
    return "\n\n".join(parts) + note


def status(prober=_probe) -> tuple[str, str]:
    """Report the assistant's capability for the GUI, without starting anything.

    Returns one of:
      ("model",   url)     — a local model server is already reachable;
      ("ready",   reason)  — a bundled/local model could be started on demand;
      ("offline", reason)  — only the built-in knowledge base is available.
    """
    ok, _kind, url = available(prober)
    if ok:
        return ("model", url)
    can, why = localmodel.availability()
    if can:
        return ("ready", why)
    return ("offline", why)


# --------------------------------------------------------------- top level
def answer(question: str, context: str = "", *, prober=_probe,
           transport=_http_post, starter=localmodel.ensure_running) -> tuple[str, bool]:
    """Answer a question. Returns (text, used_model).

    Order of preference: (1) a local model server already reachable; (2) a
    bundled/local model started on demand; (3) the offline knowledge base.
    Never raises on a model/network error — it degrades to offline.
    """
    if not (question or "").strip():
        return (offline_answer("", context), False)

    # (1) a server already listening on a known/overridden endpoint
    ok, kind, url = available(prober)
    # (2) otherwise, try to start a bundled/local model on demand (inert and
    #     returns None when no model/runtime is present, e.g. in tests)
    if not ok:
        try:
            started = starter()
        except Exception:
            started = None
        if started:
            ok, kind, url = True, "openai", started

    if ok:
        try:
            text = ask_model(question, context, kind, url, transport=transport)
            if text:
                return (text, True)
        except Exception:
            pass
    return (offline_answer(question, context), False)
