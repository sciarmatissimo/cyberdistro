"""Layer 3 — the assistant.

Design (from the feasibility study, measured on Qwen3.5-2B):
  * the model never sees strings that come from the network (DNS names,
    hostnames, user agents): ``facts()`` builds its input from layer-2 numbers,
    addresses, rule ids and our own signature names only;
  * the model only REPHRASES facts it is given; colour, urgency and confidence
    are never taken from it;
  * every answer passes ``verify()``: numbers and IPs must exist in the facts,
    completed-action verbs and outcome words are rejected unless the facts say
    so. A rejected answer falls back to the hand-written card.
  * the server starts only on demand, only with enough free RAM, listens on
    127.0.0.1 and has no tools.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from .config import Paths
from .templates import card

MIN_FREE_MB = 2600
IDLE_SECONDS = 600

SYSTEM_IT = ("Sei l'assistente di sicurezza di CyberDistro Sentinel. Riscrivi in italiano semplice, "
             "per una persona senza conoscenze tecniche, i FATTI forniti. Usa solo quei fatti: non aggiungere "
             "numeri, indirizzi, nomi, cause o esiti nuovi. Non dire che qualcosa è stato bloccato o risolto "
             "se i fatti non lo dicono. Non giudicare se la rete è sicura. Massimo due frasi per campo.")
SYSTEM_EN = ("You are the CyberDistro Sentinel security assistant. Rewrite the FACTS in plain English for a "
             "non-technical person. Use only those facts: add no new numbers, addresses, names, causes or "
             "outcomes. Never say something was blocked or fixed unless the facts say so. Do not judge whether "
             "the network is safe. At most two sentences per field.")

SCHEMA = {"type": "object", "properties": {
    "cosa_successo": {"type": "string"}, "perche_pericoloso": {"type": "string"},
    "cosa_fare": {"type": "string"}},
    "required": ["cosa_successo", "perche_pericoloso", "cosa_fare"]}

NUM_RE = re.compile(r"\d+(?:[.,]\d+)*")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
DONE_RE = re.compile(r"\b(bloccat|isolat|rimoss|eliminat|disinfettat|neutralizzat|risolt|fermat|"
                     r"blocked|isolated|removed|deleted|neutrali[sz]ed|fixed|resolved|stopped)\w*", re.I)
OUTCOME_RE = re.compile(r"\b(riuscit|compromess|violat|rubat|infett|hackerat|"
                        r"succeeded|successful|compromised|breached|stolen|infected|hacked)\w*", re.I)
# Verdicts on safety ("la rete è / non è sicura", "the network is safe") belong to layer 2.
SAFE_RE = re.compile(r"\b(rete|connessione|dispositivo|computer|pc|sistema|network|device|system)\s+"
                     r"(non\s+)?(è|e'|sia|sembra|risulta|is|seems|looks)\s+(not\s+|ora\s+|now\s+)?"
                     r"(sicur|protett|safe|secure|protected)\w*", re.I)


# ------------------------------------------------------------------ facts
def facts(inc: dict, lang: str = "it") -> str:
    """Plain-text fact sheet for the model: layer-2 values only."""
    c = card(inc, lang)
    lines = [f"- {c['title']}", f"- {c['what']}", f"- {c['why']}",
             f"- {c['level']}", f"- {c['todo']}"]
    if inc.get("facts", {}).get("login_succeeded"):
        lines.append("- Un accesso è riuscito dopo i tentativi." if lang == "it" else
                     "- A login succeeded after the attempts.")
    return "\n".join(lines)


def _numbers(text: str) -> set[str]:
    out = set()
    for n in NUM_RE.findall(text):
        out.add(n)
        out.add(n.replace(".", "").replace(",", ""))
    return out


def verify(answer: dict, fact_text: str, actions_done: bool = False) -> list[str]:
    """Return the list of problems; empty list = accepted."""
    problems = []
    if not isinstance(answer, dict) or set(SCHEMA["required"]) - set(answer):
        return ["schema"]
    text = " ".join(str(answer.get(k, "")) for k in SCHEMA["required"])
    allowed = _numbers(fact_text)
    for ip in IP_RE.findall(text):
        if ip not in fact_text:
            problems.append(f"indirizzo non presente nei fatti: {ip}")
    text_no_ip = IP_RE.sub(" ", text)
    for n in NUM_RE.findall(text_no_ip):
        if n not in allowed and n.replace(".", "").replace(",", "") not in allowed:
            problems.append(f"numero non presente nei fatti: {n}")
    if not actions_done:
        for m in DONE_RE.findall(text):
            if m.lower() not in fact_text.lower():
                problems.append(f"azione dichiarata come già fatta: {m}")
    for m in OUTCOME_RE.findall(text):
        if m.lower() not in fact_text.lower():
            problems.append(f"esito non presente nei fatti: {m}")
    for m in SAFE_RE.finditer(text):
        problems.append(f"giudizio sulla sicurezza: {m.group(0)}")
    for k in SCHEMA["required"]:
        v = str(answer.get(k, "")).strip()
        if len(v) > 400:
            problems.append(f"campo troppo lungo: {k}")
        if len(v) < 15 or v[-1] not in ".!?)\"»":
            problems.append(f"campo incompleto: {k}")
    return problems


# ------------------------------------------------------------------ server
def mem_available_mb() -> int:
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 0


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class LLM:
    def __init__(self, paths: Paths | None = None):
        self.paths = paths or Paths()
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self.last_use = 0.0

    def availability(self) -> tuple[bool, str]:
        if not self.paths.model.exists():
            return False, "modello non presente"
        if not os.access(self.paths.llama_server, os.X_OK):
            return False, "runtime llama.cpp non presente"
        if self.running():
            return True, "attivo"
        free = mem_available_mb()
        if free < MIN_FREE_MB:
            return False, f"RAM libera insufficiente ({free} MB, servono {MIN_FREE_MB} MB)"
        return True, "pronto"

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, timeout: float = 180.0) -> None:
        ok, why = self.availability()
        if not ok:
            raise RuntimeError(why)
        if self.running():
            return
        self.port = _free_port()
        threads = str(max(1, (os.cpu_count() or 2)))
        self.proc = subprocess.Popen(
            [str(self.paths.llama_server), "-m", str(self.paths.model), "-t", threads, "-c", "2048",
             "--host", "127.0.0.1", "--port", str(self.port), "--no-webui"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "LD_LIBRARY_PATH": str(self.paths.llama_server.parent)})
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                raise RuntimeError("il server del modello si è chiuso all'avvio")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=2) as r:
                    if b"ok" in r.read():
                        self.last_use = time.time()
                        return
            except OSError:
                pass
            time.sleep(1)
        self.stop()
        raise RuntimeError("il modello non è partito in tempo")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def stop_if_idle(self) -> None:
        if self.running() and time.time() - self.last_use > IDLE_SECONDS:
            self.stop()

    def complete(self, system: str, user: str, schema: dict, max_tokens: int = 450) -> dict:
        self.start()
        body = {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0.2, "max_tokens": max_tokens,
                "chat_template_kwargs": {"enable_thinking": False},
                "response_format": {"type": "json_schema", "json_schema": {"schema": schema}}}
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            d = json.loads(r.read())
        self.last_use = time.time()
        return json.loads(d["choices"][0]["message"]["content"])


# ------------------------------------------------------------------ high level
def explain(inc: dict, llm: LLM | None, lang: str = "it", actions_done: bool = False) -> dict:
    """Card for an incident; with the model, a verified plain-language rewrite.

    Returns {"card": ..., "simple": {...} | None, "source": "modello"|"scheda", "problems": [...]}"""
    c = card(inc, lang)
    out = {"card": c, "simple": None, "source": "scheda", "problems": []}
    if llm is None:
        return out
    ok, why = llm.availability()
    if not ok:
        out["problems"] = [why]
        return out
    f = facts(inc, lang)
    try:
        ans = llm.complete(SYSTEM_IT if lang == "it" else SYSTEM_EN, "FATTI:\n" + f, SCHEMA)
    except Exception as e:                      # noqa: BLE001 — any failure falls back to the card
        out["problems"] = [str(e)]
        return out
    probs = verify(ans, f, actions_done)
    if probs:
        out["problems"] = probs
        return out
    out.update(simple=ans, source="modello")
    return out


def summary_facts(status: dict, incidents: list[dict], devices: list[dict], lang: str = "it") -> str:
    open_ = [i for i in incidents if i.get("status", "aperto") == "aperto"]
    new = [d for d in devices if d.get("new")]
    lines = [f"- Stato: {status.get('colour', 'grigio')}",
             f"- Allarmi rossi: {status.get('red', 0)}, gialli: {status.get('yellow', 0)}",
             f"- Dispositivi visti: {len(devices)}, nuovi: {len(new)}"]
    for i in open_[:5]:
        lines.append("- " + card(i, lang)["title"] + f" ({i['severity']})")
    return "\n".join(lines)


def answer_question(q: str, status: dict, incidents: list[dict], devices: list[dict],
                    lang: str = "it") -> str:
    """Deterministic answers to the common questions. Always available."""
    ql = q.lower()
    now = time.time()
    open_ = [i for i in incidents if i.get("status", "aperto") == "aperto"]
    serious = [i for i in open_ if i["severity"] in ("media", "alta")]
    colour = status.get("colour", "grigio")
    new = [d for d in devices if d.get("new")]
    if any(w in ql for w in ("sicur", "safe", "tutto bene")):
        base = {"verde": "Non ho rilevato attività sospette importanti. Verde non è una garanzia: vedo solo il traffico che arriva a questo PC.",
                "giallo": f"Ho rilevato {len(serious)} attività sospette da controllare. Apri Protezione per i dettagli.",
                "rosso": f"Ci sono {status.get('red', 0)} eventi gravi confermati. Apri Protezione e segui le istruzioni.",
                "grigio": "Il monitoraggio non è completo, quindi non posso dirlo. Controlla la connessione."}
        return base.get(colour, base["grigio"])
    if any(w in ql for w in ("attacc", "attack")):
        att = [i for i in serious if i["rule"] in ("port_scan", "brute_force", "arp_spoof", "host_sweep", "lateral_movement")]
        if not att:
            return "Non vedo tentativi di attacco in corso tra quelli che so riconoscere."
        return "Sì, vedo: " + "; ".join(card(i, lang)["title"] + f" da {i.get('src') or i['facts'].get('new_mac') or '?'}" for i in att[:5]) + "."
    if any(w in ql for w in ("sconosciut", "nuov", "unknown", "new device")):
        if not new:
            return f"Nessun dispositivo nuovo dall'avvio. Dispositivi visti: {len(devices)}."
        return "Dispositivi comparsi dopo l'avvio: " + ", ".join(d.get("ip") or d.get("mac") or "?" for d in new[:10]) + "."
    if any(w in ql for w in ("ultima ora", "last hour", "insolit", "unusual")):
        recent = [i for i in incidents if now - i["last_ts"] <= 3600]
        if not recent:
            return "Nell'ultima ora non ho registrato nulla di insolito."
        return f"Nell'ultima ora: {len(recent)} eventi. " + "; ".join(card(i, lang)["title"] for i in recent[:5]) + "."
    if any(w in ql for w in ("cosa devo fare", "cosa faccio", "what should i do", "what do i do")):
        if not serious:
            return "Al momento non serve fare nulla. Lascia attivo il monitoraggio."
        top = sorted(serious, key=lambda i: (i["severity"] != "alta", -i["last_ts"]))[0]
        return card(top, lang)["todo"]
    return ""


SCHEMA_Q = {"type": "object", "properties": {"risposta": {"type": "string"}}, "required": ["risposta"]}
SYSTEM_Q_IT = ("Sei l'assistente di sicurezza di CyberDistro Sentinel. Rispondi in italiano semplice alla domanda "
               "dell'utente usando SOLO i FATTI forniti sulla sua rete. Se i fatti non bastano, dillo. Non inventare "
               "numeri, indirizzi o eventi. Non dire che la rete è sicura o che qualcosa è stato bloccato. "
               "Massimo quattro frasi.")
SYSTEM_Q_EN = ("You are the CyberDistro Sentinel security assistant. Answer the user's question in plain English "
               "using ONLY the FACTS about their network. If the facts are not enough, say so. Never invent numbers, "
               "addresses or events. Never say the network is safe or that something was blocked. At most four sentences.")


def answer_free(question: str, fact_text: str, llm: LLM, lang: str = "it") -> tuple[str | None, list[str]]:
    """Free question → model answer grounded on ``fact_text``; None if rejected."""
    ok, why = llm.availability()
    if not ok:
        return None, [why]
    try:
        ans = llm.complete(SYSTEM_Q_IT if lang == "it" else SYSTEM_Q_EN,
                           f"FATTI:\n{fact_text}\n\nDOMANDA: {question[:500]}", SCHEMA_Q, max_tokens=300)
    except Exception as e:                      # noqa: BLE001
        return None, [str(e)]
    text = str(ans.get("risposta", "")).strip()
    probs = verify({"cosa_successo": text, "perche_pericoloso": "Nessun campo aggiuntivo.",
                    "cosa_fare": "Nessun campo aggiuntivo."}, fact_text + "\nNessun campo aggiuntivo. " + question)
    return (None, probs) if probs else (text, [])
