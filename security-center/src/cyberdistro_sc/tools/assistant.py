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
    (r"\b(https|cifrat|encrypt|leggere i contenut|contents)\b",
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
    (r"\b(bridge|ponte|due schede|trasparent|transparent)\b",
     ("Il «bridge trasparente» unisce le due schede di rete in un ponte senza "
      "indirizzo IP: il PC diventa invisibile e, messo tra il router e il resto "
      "della rete, lascia passare tutto il traffico e te lo mostra. È solo "
      "osservazione: non modifica nulla.",
      "The 'transparent bridge' joins the two network cards into a bridge with "
      "no IP address: the PC becomes invisible and, placed between the router "
      "and the rest of the network, lets all traffic through and shows it to "
      "you. It is observation only: it changes nothing.")),
    (r"\b(device|dispositiv|chi c'è|who is|mac)\b",
     ("Ogni tile è un dispositivo visto sulla rete, identificato dal suo "
      "indirizzo IP e MAC; sotto trovi quanti pacchetti ha generato e quanti "
      "siti ha contattato. Un MAC «casuale» significa che il dispositivo "
      "nasconde il produttore (privacy).",
      "Each tile is a device seen on the network, identified by its IP and MAC "
      "address; below it you see how many packets it generated and how many "
      "sites it contacted. A 'random' MAC means the device hides its vendor "
      "(privacy).")),
    (r"\b(sit[oi]|site|dns|domin|domain)\b",
     ("I «siti contattati» sono i nomi di dominio che i dispositivi hanno "
      "cercato (DNS) o aperto in HTTPS (campo SNI). Un sito contattato spesso "
      "non significa per forza che l'utente lo stia visitando: molte app e "
      "servizi contattano domini in background.",
      "The 'sites contacted' are the domain names devices looked up (DNS) or "
      "opened over HTTPS (SNI field). A frequently contacted site does not "
      "necessarily mean the user is visiting it: many apps and services contact "
      "domains in the background.")),
    (r"\b(tor|anonim|anonym|privacy)\b",
     ("Per navigare in modo anonimo usa la sezione Privacy e Tor Browser. La "
      "modalità «Anonimato Tor» attiva un kill-switch: se Tor cade, non esce "
      "traffico. L'anonimato non è mai assoluto: attenzione ad account "
      "personali, fingerprinting e metadati.",
      "To browse anonymously use the Privacy section and Tor Browser. The 'Tor "
      "anonymity' mode enables a kill-switch: if Tor drops, no traffic leaves. "
      "Anonymity is never absolute: beware of personal accounts, fingerprinting "
      "and metadata.")),
    (r"\b(autorizz|legal|permess|allowed|authori[sz])\b",
     ("Usa il monitoraggio solo sulla tua rete o su una rete per cui hai "
      "l'autorizzazione. Intercettare il traffico di una rete altrui senza "
      "consenso è illegale.",
      "Use monitoring only on your own network or one you are authorized to "
      "monitor. Intercepting someone else's network traffic without consent is "
      "illegal.")),
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
        parts.extend(hits[:2])
    else:
        parts.append(
            "Posso aiutarti con il Monitor di rete, la privacy/Tor, la forense e "
            "gli strumenti di CyberDistro. Riformula la domanda o chiedimi, ad "
            "esempio, «cosa vedo con il bridge?» o «perché non leggo i "
            "contenuti?»." if it else
            "I can help with the Network Monitor, privacy/Tor, forensics and "
            "CyberDistro's tools. Rephrase your question or ask me, for example, "
            "“what do I see with the bridge?” or “why can't I read the "
            "contents?”.")
    if context.strip():
        parts.append(("Sul traffico osservato adesso: " if it
                      else "About the traffic observed now: ") + summarize_context(context))
    note = ("\n\n(Assistente in modalità base: nessun modello AI locale attivo. "
            "Con un modello locale avviato posso rispondere a domande libere.)" if it else
            "\n\n(Assistant in basic mode: no local AI model running. With a "
            "local model started I can answer free-form questions.)")
    return "\n\n".join(parts) + note


# --------------------------------------------------------------- top level
def answer(question: str, context: str = "", *, prober=_probe,
           transport=_http_post) -> tuple[str, bool]:
    """Answer a question. Returns (text, used_model).

    Uses a local model if one is reachable; otherwise the offline knowledge
    base. Never raises on a model/network error — it degrades to offline.
    """
    if not (question or "").strip():
        return (offline_answer("", context), False)
    ok, kind, url = available(prober)
    if ok:
        try:
            text = ask_model(question, context, kind, url, transport=transport)
            if text:
                return (text, True)
        except Exception:
            pass
    return (offline_answer(question, context), False)
