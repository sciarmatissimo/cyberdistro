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
from .devices import TYPE_LABEL, guess_type, vendor
from .knowledge import describe_port, ports_from_result, summarize_ports
from .templates import addr, card

MIN_FREE_MB = 2600          # measured: llama-server RSS 2.0–2.3 GB with this model
CTX_TOKENS = 3072
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


def verify(answer: dict, fact_text: str, actions_done: bool = False, max_len: int = 400) -> list[str]:
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
        if len(v) > max_len:
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
            [str(self.paths.llama_server), "-m", str(self.paths.model), "-t", threads, "-c", str(CTX_TOKENS),
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


def _when(ts) -> str:
    return time.strftime("%d/%m %H:%M", time.localtime(ts)) if ts else "?"


def _scans(actions: list[dict]) -> list[dict]:
    return [a for a in actions if a.get("action", "").startswith("scansione")]


def last_scan_of(ip: str, actions: list[dict]) -> dict | None:
    for a in _scans(actions):                   # actions are newest first
        if a.get("target") == ip and a.get("end_ts"):
            return a
    return None


def describe_device(d: dict, incidents: list[dict], actions: list[dict], lang: str = "it") -> str:
    """Deterministic description of one device (no network-supplied names)."""
    ip = d.get("ip") or "?"
    t = TYPE_LABEL["it" if lang != "en" else "en"][guess_type(d)]
    parts = [f"{ip}: {t}" + ("" if guess_type(d) in ("self", "router") else " (probabile)")]
    v = vendor(d.get("mac"))
    if v:
        parts.append(f"produttore {v}" if lang != "en" else f"maker {v}")
    if d.get("new"):
        parts.append("comparso dopo l'avvio" if lang != "en" else "appeared after start")
    rel = [i for i in incidents if ip in (i.get("src"), i.get("dst")) and i["severity"] != "bassa"
           and i.get("status", "aperto") == "aperto"]
    parts.append((f"allarmi aperti {len(rel)}" if lang != "en" else f"open alerts {len(rel)}"))
    sc = last_scan_of(ip, actions)
    if sc:
        ports = ports_from_result(sc.get("result", ""))
        if ports:
            ps = ", ".join(f"{p} {describe_port(p, lang)['name']} (rischio {describe_port(p, lang)['risk']})" for p in ports[:10])
            parts.append(f"l'utente lo ha esaminato il {_when(sc['ts'])} e ha trovato questi servizi attivi "
                         f"(porte aperte, non attacchi): {ps}")
        else:
            parts.append(f"l'utente lo ha esaminato il {_when(sc['ts'])}: nessuna porta comune aperta")
    return "; ".join(parts)


def network_facts(status: dict, incidents: list[dict], devices: list[dict], actions: list[dict] | None = None,
                  lang: str = "it") -> str:
    """Fact sheet about the whole network for free questions (layer-2 data only,
    plus our own vendor table and port knowledge; no names announced by devices)."""
    actions = actions or []
    me = next((d.get("ip") for d in devices if d.get("is_self")), None)
    gw = next((d.get("ip") for d in devices if d.get("is_gateway")), None)
    open_ = [i for i in incidents if i.get("status", "aperto") == "aperto"]
    new = [d for d in devices if d.get("new")]
    lines = ["RETE:",
             f"- Questo PC (dove gira Sentinel): {me or 'sconosciuto'}",
             f"- Router: {gw or 'sconosciuto'}",
             f"- Stato: {status.get('colour', 'grigio')}; allarmi rossi {status.get('red', 0)}, gialli {status.get('yellow', 0)}",
             f"- Dispositivi visti: {len(devices)}, comparsi dopo l'avvio: {len(new)}",
             "- Sentinel vede solo il traffico che arriva a questo PC, non quello tra gli altri dispositivi.",
             "DISPOSITIVI:"]
    for d in devices[:40]:
        lines.append("- " + describe_device(d, incidents, actions, lang))
    lines.append("ALLARMI APERTI (dal più recente):")
    serious = [i for i in open_ if i["severity"] != "bassa"]
    for i in serious[:10]:
        c = card(i, lang)
        lines.append(f"- [{i['severity']}, {i['level']}] {c['title']}: {c['what']} Cosa fare: {c['todo']}")
    if not serious:
        lines.append("- nessuno di gravità media o alta")
    info = [i for i in open_ if i["severity"] == "bassa" and i["rule"] != "new_device"]
    if info:
        lines.append("EVENTI INFORMATIVI:")
        for i in info[:6]:
            lines.append(f"- {card(i, lang)['title']}")
    sc = _scans(actions)
    if sc:
        lines.append("ESAMI AVVIATI DALL'UTENTE:")
        for a in sc[:8]:
            lines.append(f"- {_when(a['ts'])} {a['action']} di {a['target']}: {a.get('result') or 'in corso'}")
    return "\n".join(lines)


def summary_facts(status: dict, incidents: list[dict], devices: list[dict], lang: str = "it") -> str:
    """Kept for compatibility: the network fact sheet without actions."""
    return network_facts(status, incidents, devices, [], lang)


HYGIENE_IT = [
    "Cambia la password di amministrazione del router se è ancora quella scritta sull'etichetta.",
    "Aggiorna il firmware del router e dei dispositivi smart (telecamere, prese, TV).",
    "Usa la cifratura WPA2 o WPA3 per il Wi-Fi e disattiva il WPS.",
    "Se il router lo permette, metti i dispositivi smart su una rete ospiti separata.",
    "Disattiva l'UPnP sul router se non ti serve.",
]


def action_plan(status: dict, incidents: list[dict], devices: list[dict], actions: list[dict] | None = None,
                lang: str = "it") -> list[str]:
    """What to do now, most urgent first, from layer-2 facts, examinations and our
    own knowledge. Deterministic: the same situation always gives the same plan."""
    actions = actions or []
    steps = []
    open_ = [i for i in incidents if i.get("status", "aperto") == "aperto" and i["severity"] != "bassa"]
    order = {"alta": 0, "media": 1}
    seen = set()
    for i in sorted(open_, key=lambda i: (order.get(i["severity"], 2), -i["last_ts"])):
        c = card(i, lang)
        if c["todo"] in seen:
            continue
        seen.add(c["todo"])
        tag = "URGENTE" if i["severity"] == "alta" else "Presto"
        steps.append(f"[{tag}] {c['title']}: {c['todo']}")
    risky = []
    for d in devices:
        sc = last_scan_of(d.get("ip"), actions) if d.get("ip") else None
        for p in ports_from_result(sc.get("result", "")) if sc else []:
            info = describe_port(p, lang)
            if info["risk"] in ("alta", "media"):
                risky.append((0 if info["risk"] == "alta" else 1, d["ip"], p, info))
    for r, ip, p, info in sorted(risky)[:8]:
        steps.append(f"[{'Importante' if r == 0 else 'Consigliato'}] {ip}, porta {p} – {info['name']}: {info['advice']}")
    new = [d for d in devices if d.get("new")]
    if new:
        steps.append(f"[Controlla] {len(new)} dispositivi sono comparsi dopo l'avvio: verifica nella sezione Rete "
                     "di riconoscerli. Se uno non è tuo, cambia la password del Wi-Fi.")
    scanned = {a.get("target") for a in _scans(actions) if a.get("end_ts")}
    unexamined = [d for d in devices if not d.get("is_self") and d.get("ip") and ":" not in d["ip"]
                  and d["ip"] not in scanned]
    if unexamined:
        steps.append(f"[Suggerito] {len(unexamined)} dispositivi non sono ancora stati esaminati: in Rete selezionane "
                     "uno e usa «Esamina questo dispositivo» per scoprire servizi rischiosi (solo sulla tua rete).")
    steps += [f"[Buona pratica] {h}" for h in HYGIENE_IT]
    return steps


TYPE_WORDS = {"phone": ("telefon", "cellular", "smartphone", "phone"), "pc": ("computer", "pc", "portatil", "laptop"),
              "printer": ("stampant", "printer"), "tv": ("tv", "televis", "chromecast"),
              "iot": ("smart", "iot", "telecamer", "camera"), "router": ("router",),
              "unknown": ("sconosciut", "unknown")}
IP_Q = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def answer_question(q: str, status: dict, incidents: list[dict], devices: list[dict],
                    lang: str = "it", actions: list[dict] | None = None) -> str:
    """Deterministic answers to the common questions. Always available."""
    ql = q.lower()
    now = time.time()
    actions = actions or []
    m = IP_Q.search(q)
    if m:                                       # "chi è 192.168.1.20?" — anything about one address
        ip = m.group(1)
        d = next((x for x in devices if x.get("ip") == ip), None)
        if d is None:
            return f"Non ho visto nessun dispositivo con indirizzo {ip}."
        rel = [i for i in incidents if ip in (i.get("src"), i.get("dst")) and i.get("status", "aperto") == "aperto"]
        txt = describe_device(d, incidents, actions, lang) + "."
        if rel:
            txt += " Eventi che lo riguardano: " + " ".join(card(i, lang)["what"] for i in rel[:5])
        sc = last_scan_of(ip, actions)
        if sc and ports_from_result(sc.get("result", "")):
            txt += "\n" + summarize_ports(ports_from_result(sc["result"]), lang)
        elif not sc and not d.get("is_self"):
            txt += " Per sapere quali servizi espone, selezionalo nella sezione Rete e usa «Esamina questo dispositivo»."
        return txt
    if any(w in ql for w in ("quanti", "quante", "how many")):
        for t, words in TYPE_WORDS.items():
            if any(w in ql for w in words):
                found = [d for d in devices if guess_type(d) == t]
                lab = TYPE_LABEL["it" if lang != "en" else "en"][t]
                return (f"{lab}: {len(found)} (stima dal produttore della scheda di rete e dai servizi annunciati)"
                        + (": " + ", ".join(d.get("ip") or "?" for d in found[:15]) if found else "") + ".")
        if any(w in ql for w in ("windows", "mac", "linux", "iphone", "android")):
            return ("Non so riconoscere il sistema operativo dei dispositivi in modo affidabile: vedo solo il "
                    "produttore della scheda di rete e i servizi annunciati. Posso dirti quanti computer, telefoni, "
                    "stampanti o dispositivi smart ci sono, e con «Esamina questo dispositivo» quali porte aprono.")
    if any(w in ql for w in ("scansion", "porte apert", "esame", "esaminat", "scan", "open port")):
        sc = [a for a in _scans(actions) if a.get("end_ts")]
        if not sc:
            return ("Non hai ancora esaminato nessun dispositivo. Vai in Rete, seleziona un dispositivo e usa "
                    "«Esamina questo dispositivo (Nmap)», oppure «Esamina la rete» dalla Home.")
        out = []
        for a in sc[:5]:
            ports = ports_from_result(a.get("result", ""))
            risky = [p for p in ports if describe_port(p, lang)["risk"] == "alta"]
            out.append(f"{_when(a['ts'])} {a['target']}: " + (a.get("result") or "")
                       + (f" — porte a rischio alto: {', '.join(map(str, risky))}" if risky else ""))
        return "Ultimi esami:\n" + "\n".join(out)
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
        att = [i for i in serious if i["rule"] in ("port_scan", "brute_force", "arp_spoof", "host_sweep",
                                                     "lateral_movement", "own_scan")]
        mine = [i for i in open_ if i["rule"] == "own_scan" and i["facts"].get("by_user")]
        if not att:
            return ("Non vedo tentativi di attacco in corso tra quelli che so riconoscere."
                    + (" Le scansioni che hai avviato tu non sono attacchi e le registro a parte." if mine else ""))
        return "Sì, vedo: " + "; ".join(
            card(i, lang)["title"] + (" (origine: " + (addr(i.get("src"), i["facts"].get("src_role"), lang)
                                                      if i.get("src") else (i["facts"].get("new_mac") or "?")) + ")")
            for i in att[:5]) + "."
    if any(w in ql for w in ("sconosciut", "nuov", "unknown", "new device")):
        if not new:
            return f"Nessun dispositivo nuovo dall'avvio. Dispositivi visti: {len(devices)}."
        return "Dispositivi comparsi dopo l'avvio: " + ", ".join(d.get("ip") or d.get("mac") or "?" for d in new[:10]) + "."
    if any(w in ql for w in ("ultima ora", "last hour", "insolit", "unusual")):
        recent = [i for i in incidents if now - i["last_ts"] <= 3600]
        if not recent:
            return "Nell'ultima ora non ho registrato nulla di insolito."
        return f"Nell'ultima ora: {len(recent)} eventi. " + "; ".join(card(i, lang)["title"] for i in recent[:5]) + "."
    if any(w in ql for w in ("cosa devo fare", "cosa faccio", "what should i do", "what do i do", "consigl",
                             "preoccup", "pericol", "protegg", "più sicur", "piu sicur", "miglior")):
        plan = action_plan(status, incidents, devices, actions, lang)
        urgent = [x for x in plan if not x.startswith("[Buona pratica]")]
        head = ("Ecco cosa ti consiglio, dal più urgente:" if urgent else
                "Non vedo problemi da risolvere adesso. Per rendere la rete più sicura:")
        return head + "\n" + "\n".join(f"{n}. {x}" for n, x in enumerate((urgent + plan[len(urgent):])[:10], 1))
    return ""


SCHEMA_Q = {"type": "object", "properties": {"risposta": {"type": "string"}}, "required": ["risposta"]}
SYSTEM_Q_IT = ("Sei l'assistente di sicurezza di CyberDistro Sentinel. Rispondi in italiano semplice alla domanda "
               "dell'utente usando SOLO i FATTI forniti sulla sua rete. Se i fatti non bastano, dillo. Non inventare "
               "numeri, indirizzi o eventi. Regole: attribuisci ogni evento esattamente al dispositivo indicato nei "
               "fatti come origine; le porte aperte sono servizi attivi trovati dagli esami dell'utente, non attacchi; "
               "le scansioni avviate dall'utente non sono attacchi; non dire di chi è un dispositivo né se è "
               "autorizzato; non dire che la rete è sicura o che qualcosa è stato bloccato. Per i consigli usa le "
               "indicazioni «Cosa fare» e i rischi delle porte presenti nei fatti. Massimo quattro frasi.")
SYSTEM_Q_EN = ("You are the CyberDistro Sentinel security assistant. Answer the user's question in plain English "
               "using ONLY the FACTS about their network. If the facts are not enough, say so. Never invent numbers, "
               "addresses or events. Attribute each event exactly to the source device in the facts; open ports are "
               "running services found by the user's own examinations, not attacks; scans the user started are not "
               "attacks; never say who owns a device or whether it is authorised; never say the network is safe or "
               "that something was blocked. At most four sentences.")


def answer_free(question: str, fact_text: str, llm: LLM, lang: str = "it") -> tuple[str | None, list[str]]:
    """Free question → model answer grounded on ``fact_text``; None if rejected."""
    ok, why = llm.availability()
    if not ok:
        return None, [why]
    try:
        ans = llm.complete(SYSTEM_Q_IT if lang == "it" else SYSTEM_Q_EN,
                           f"FATTI:\n{fact_text}\n\nDOMANDA: {question[:500]}", SCHEMA_Q, max_tokens=420)
    except Exception as e:                      # noqa: BLE001
        return None, [str(e)]
    text = str(ans.get("risposta", "")).strip()
    probs = verify({"cosa_successo": text, "perche_pericoloso": "Nessun campo aggiuntivo.",
                    "cosa_fare": "Nessun campo aggiuntivo."}, fact_text + "\nNessun campo aggiuntivo. " + question,
                   max_len=900)
    return (None, probs) if probs else (text, [])
