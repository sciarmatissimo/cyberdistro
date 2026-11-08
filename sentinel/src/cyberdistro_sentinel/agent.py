"""Sentinel agent (0.3): turns alarms into defensive actions the user can approve.

Layer 2 decides *that* something happened; the agent decides *what can be done
about it on this PC*, using hand-written playbooks and a closed list of tools.
The language model never chooses or runs an action: it can only explain a
proposal (through the verifier) in the Security Center.

Autonomy levels (meta key ``agent_level``):
  osserva  — the agent writes advice only;
  chiede   — the agent prepares actions and waits for "Approva" (default).
Passive steps (collecting context from the logs Sentinel already has) run on
their own at every level, because they change nothing.

Safety rules, also enforced again by /usr/local/sbin/sentinel-action:
  * never act against this PC, the router or the DNS servers;
  * blocks expire after 24 hours; everything can be undone;
  * at most MAX_PER_HOUR new proposals per hour; one task per action+target;
  * Nmap examinations of other devices only on a network the user declared
    as their own;
  * "Ferma l'agente" (meta ``agent_paused``) stops new proposals.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from collections import Counter
from pathlib import Path

from .config import Paths
from .events import read_jsonl
from .knowledge import parse_nmap_open, summarize_ports
from .store import Store
from .templates import card

LEVELS = ("osserva", "chiede", "auto")
DEFAULT_LEVEL = "chiede"
# In "auto" the Security Center runs these local, reversible, time-limited actions
# itself without asking; examine (actively scans another device) and the deep
# inspection are never automatic.
AUTO_ACTIONS = ("block", "pin_gateway", "capture")
MAX_PER_HOUR = 12
BLOCK_HOURS = 24
LOOKBACK = 3600.0
ACTION_HELPER = "/usr/local/sbin/sentinel-action"

# statuses
CONSIGLIO, PROPOSTA, IN_CORSO, ATTIVA, COMPLETATA = "consiglio", "proposta", "in_corso", "attiva", "completata"
RIFIUTATA, ANNULLATA, SCADUTA, ERRORE = "rifiutata", "annullata", "scaduta", "errore"
OPEN_STATES = {CONSIGLIO, PROPOSTA, IN_CORSO, ATTIVA}

ACTION_LABEL = {
    "block": "Bloccare {target} su questo PC per 24 ore",
    "pin_gateway": "Fissare su questo PC il vero indirizzo del router ({target})",
    "capture": "Salvare 60 secondi del traffico di {target} come prova",
    "examine": "Esaminare {target} con Nmap (100 porte comuni)",
    "context": "Raccogliere il contesto su {target}",
}
ACTION_EFFECT = {
    "block": "Questo PC smette di ricevere e inviare traffico a {target}. Gli altri dispositivi della rete non "
             "vengono toccati. Il blocco scade da solo dopo 24 ore e puoi annullarlo quando vuoi.",
    "pin_gateway": "Il router vero ha la scheda di rete {mac}. Fissandola, questo PC ignora chi si spaccia per il "
                   "router. Vale fino al riavvio e puoi annullarlo.",
    "capture": "Il file di cattura resta su questo PC (cartella /var/lib/sentinel/evidence) e serve a un tecnico per "
               "capire cosa è successo. Non viene inviato a nessuno.",
    "examine": "Scopre quali servizi espone il dispositivo e quanto sono rischiosi. È proposto solo perché hai "
               "dichiarato che questa è la tua rete.",
    "context": "Legge solo i registri che Sentinel ha già: non cambia nulla e non invia nulla.",
}
ATTACK_RULES = {"port_scan", "host_sweep", "brute_force", "lateral_movement", "suricata_alert"}


def lc(text: str) -> str:
    """Lower-case only the first letter ("Bloccare … questo PC" → "bloccare … questo PC")."""
    return text[:1].lower() + text[1:]


def label(task: dict) -> str:
    return ACTION_LABEL.get(task["action"], task["action"]).format(target=task["target"])


def effect(task: dict) -> str:
    return ACTION_EFFECT.get(task["action"], "").format(target=task["target"], mac=task["params"].get("mac", "?"))


# ------------------------------------------------------------------ context
def resolvers(path: str = "/etc/resolv.conf") -> set[str]:
    out = set()
    try:
        for line in Path(path).read_text().splitlines():
            f = line.split()
            if len(f) >= 2 and f[0] == "nameserver":
                out.add(f[1])
    except OSError:
        pass
    return out


def default_gateway(path: str = "/proc/net/route") -> str | None:
    """IPv4 default gateway from the kernel routing table (authoritative)."""
    try:
        for line in Path(path).read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 2 and f[1] == "00000000" and f[2] != "00000000":
                return str(ipaddress.IPv4Address(bytes.fromhex(f[2])[::-1]))
    except (OSError, ValueError):
        pass
    return None


def local_ips(path: str = "/proc/net/fib_trie") -> set[str]:
    """Every IPv4 address of this PC (LOCAL entries of the kernel routing trie)."""
    out, last = set(), None
    try:
        for line in Path(path).read_text().splitlines():
            t = line.strip()
            if t.startswith("|--"):
                last = t[3:].strip()
            elif "/32 host LOCAL" in t and last:
                out.add(last)
    except OSError:
        pass
    return out - {"127.0.0.1"}


def network_ctx(store: Store) -> dict:
    """Who is who. The router and this PC's addresses come from the kernel (a device
    row can carry another address of the same card, e.g. an IPv6 one); the router's
    real hardware address comes from what Sentinel learned first."""
    devs = store.devices()
    me = next((d for d in devs if d.get("is_self")), {})
    gwd = next((d for d in devs if d.get("is_gateway")), {})
    mine = local_ips() | ({me["ip"]} if me.get("ip") else set())
    gw = default_gateway() or gwd.get("ip")
    return {"self_ip": me.get("ip") or next(iter(sorted(mine)), None), "self_ips": mine, "gateway": gw,
            "gateway_mac": gwd.get("mac"), "resolvers": resolvers(),
            "devices": {d.get("ip"): d for d in devs if d.get("ip")}}


def safe_target(ip, ctx) -> tuple[bool, str]:
    """May the agent act against ``ip``? Returns (ok, reason if not)."""
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False, "indirizzo non valido"
    if a.version != 4 or a.is_loopback or a.is_multicast or a.is_unspecified or str(a).endswith(".255"):
        return False, "indirizzo speciale"
    if ip == ctx.get("self_ip") or ip in ctx.get("self_ips", ()):
        return False, "è questo PC"
    if ip == ctx.get("gateway"):
        return False, "è il router: bloccarlo interromperebbe la connessione"
    if ip in ctx.get("resolvers", ()):
        return False, "è il server DNS in uso"
    return True, ""


def is_internal(ip) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ------------------------------------------------------------------ playbooks
def plan(inc: dict, ctx: dict, own_network: bool) -> list[dict]:
    """Steps for one open incident: [{action, target, params, reason}]. Deterministic."""
    f = inc.get("facts", {})
    rule, sev = inc["rule"], inc["severity"]
    c = card(inc)
    why = f"{c['title']}. {c['what']}"
    steps = []

    def add(action, target, **params):
        if target:
            steps.append({"action": action, "target": target, "params": params, "reason": why})

    if rule == "new_device":
        ip = f.get("ip") or inc.get("src")
        if own_network and not f.get("found_by_scan") and safe_target(ip, ctx)[0] and is_internal(ip):
            add("examine", ip)
        return steps
    if sev == "bassa" or f.get("informational") or f.get("by_user"):
        return steps

    if rule in ATTACK_RULES:
        attacker = inc.get("src")
        if attacker == ctx.get("self_ip"):            # this PC talking to a bad server
            attacker = inc.get("dst")
        add("context", attacker)
        if safe_target(attacker, ctx)[0]:
            add("block", attacker)
            if sev == "alta":
                add("capture", attacker)
    elif rule == "arp_spoof":
        ip = f.get("ip") or inc.get("dst")
        if f.get("is_gateway") and f.get("old_mac") and ip == ctx.get("gateway"):
            add("pin_gateway", ip, mac=f["old_mac"], fake_mac=f.get("new_mac"))
        add("context", ip)
    elif rule in ("beaconing", "exfiltration"):
        src, dst = inc.get("src"), inc.get("dst")
        add("context", src)
        if src == ctx.get("self_ip") and safe_target(dst, ctx)[0]:
            add("block", dst)                          # stop this PC talking to that server
            add("capture", dst)
    elif rule in ("dns_tunnel", "dns_nxdomain_burst", "arp_multi_ip", "own_scan"):
        add("context", inc.get("src") or f.get("ip") or ctx.get("self_ip"))
    return steps


# ------------------------------------------------------------------ passive context
def collect_context(ip: str, paths: Paths, around: tuple[float, float], max_lines: int = 200000) -> dict:
    """Summarise what Zeek already logged about ``ip`` (connections, DNS) around an incident."""
    t0, t1 = around[0] - 600, around[1] + 120
    conns, peers, ports, out_b, in_b = 0, Counter(), Counter(), 0, 0
    states = Counter()
    for rec in _tail(paths.zeek_dir / "conn.log", max_lines):
        ts = rec.get("ts", 0)
        if not (t0 <= ts <= t1):
            continue
        o, r = rec.get("id.orig_h"), rec.get("id.resp_h")
        if ip not in (o, r):
            continue
        conns += 1
        peer = r if o == ip else o
        peers[peer] += 1
        if o == ip:
            ports[rec.get("id.resp_p")] += 1
            out_b += rec.get("orig_bytes") or 0
            in_b += rec.get("resp_bytes") or 0
        states[rec.get("conn_state")] += 1
    dns_q, names = 0, Counter()
    for rec in _tail(paths.zeek_dir / "dns.log", max_lines):
        if rec.get("id.orig_h") == ip and t0 <= rec.get("ts", 0) <= t1:
            dns_q += 1
            if rec.get("query"):
                names[str(rec["query"])[:80]] += 1
    return {"ip": ip, "connections": conns, "peers": len(peers),
            "top_peers": [p for p, _ in peers.most_common(5)],
            "top_ports": [int(p) for p, _ in ports.most_common(8) if p is not None],
            "bytes_out": out_b, "bytes_in": in_b,
            "failed": states.get("REJ", 0) + states.get("S0", 0),
            "dns_queries": dns_q,
            # names come from the network: shown (escaped) to the user, never given to the model
            "dns_names": [n for n, _ in names.most_common(10)]}


def _tail(path: Path, max_lines: int):
    try:
        recs = list(read_jsonl(path))
    except OSError:
        return []
    return recs[-max_lines:]


def context_text(r: dict) -> str:
    if not r:
        return ""
    peers = "1 indirizzo" if r["peers"] == 1 else f"{r['peers']} indirizzi diversi"
    t = (f"Nei registri: {r['connections']} connessioni con {peers}"
         + (f", di cui {r['failed']} rifiutate o senza risposta" if r.get("failed") else "")
         + f"; {r['dns_queries']} ricerche DNS.")
    if r.get("top_ports"):
        t += " Porte contattate più spesso: " + ", ".join(map(str, r["top_ports"])) + "."
    if r.get("bytes_out") or r.get("bytes_in"):
        t += f" Dati inviati {r['bytes_out'] // 1024} KB, ricevuti {r['bytes_in'] // 1024} KB."
    return t


# ------------------------------------------------------------------ execution (GUI / tests)
def execute(store: Store, task: dict, runner, priv: list[str]) -> dict:
    """Run an approved task. ``runner(cmd, timeout) -> (code, output)``; ``priv`` is the
    privilege prefix (["pkexec"] in the Security Center). Returns the updated task."""
    a, ip, tid = task["action"], task["target"], task["id"]
    store.update_task(tid, status=IN_CORSO)
    try:
        if a == "block":
            code, out = runner(priv + [ACTION_HELPER, "block", ip, str(BLOCK_HOURS)], 30)
            if code == 0:
                store.update_task(tid, status=ATTIVA, expires_ts=time.time() + BLOCK_HOURS * 3600,
                                  result={"output": out.strip()[:300]})
                store.log_action("blocco 24 ore", ip, "agente: " + out.strip()[:150])
        elif a == "pin_gateway":
            code, out = runner(priv + [ACTION_HELPER, "pin-gateway", ip, task["params"]["mac"]], 30)
            if code == 0:
                store.update_task(tid, status=ATTIVA, result={"output": out.strip()[:300]})
        elif a == "capture":
            code, out = runner(priv + [ACTION_HELPER, "capture", ip, "60"], 120)
            if code == 0:
                store.update_task(tid, status=COMPLETATA, result={"file": out.strip().splitlines()[-1][:300]})
        elif a == "examine":
            aid = store.log_action("scansione dispositivo", ip, "in corso (agente)")
            code, out = runner(["nmap", "-Pn", "-sT", "-F", "-T3", ip], 600)
            ports = parse_nmap_open(out)
            ok = code == 0 and "Nmap done" in out
            res = (("porte aperte: " + ", ".join(map(str, ports))) if ports else "nessuna porta comune aperta") \
                if ok else "esame non riuscito"
            store.finish_action(aid, res)
            if ok:
                store.update_task(tid, status=COMPLETATA, result={"ports": ports, "summary": summarize_ports(ports)})
            code = 0 if ok else 1
        else:
            code, out = 2, f"azione sconosciuta: {a}"
    except Exception as e:                          # noqa: BLE001
        code, out = 1, str(e)
    if code != 0:
        store.update_task(tid, status=ERRORE, result={"output": (out or "").strip()[:300]})
        store.agent_log(f"Non sono riuscito a: {lc(label(task))} — {(out or '').strip()[:160]}", tid)
    else:
        done = store.task(tid)
        detail = ""
        r = done.get("result") if isinstance(done.get("result"), dict) else {}
        if a == "examine":
            ports = r.get("ports") or []
            detail = (" Porte aperte trovate: " + ", ".join(map(str, ports)) + "."
                      if ports else " Nessuna porta comune aperta.")
        elif a == "capture" and r.get("file"):
            detail = " File: " + r["file"].rsplit("/", 1)[-1] + "."
        store.agent_log(f"Fatto: {lc(label(task))}.{detail}", tid)
    return store.task(tid)


def undo(store: Store, task: dict, runner, priv: list[str]) -> dict:
    a, ip, tid = task["action"], task["target"], task["id"]
    if a == "block":
        code, out = runner(priv + [ACTION_HELPER, "unblock", ip], 30)
    elif a == "pin_gateway":
        code, out = runner(priv + [ACTION_HELPER, "unpin-gateway", ip], 30)
    else:
        code, out = 0, ""
    if code == 0:
        store.update_task(tid, status=ANNULLATA)
        store.agent_log(f"Annullato: {lc(label(task))}.", tid)
    else:
        store.agent_log(f"Non sono riuscito ad annullare: {lc(label(task))} — {out.strip()[:160]}", tid)
    return store.task(tid)


def reject(store: Store, task: dict, why: str = "rifiutata dall'utente") -> None:
    store.update_task(task["id"], status=RIFIUTATA, result={"output": why})
    store.agent_log(f"Proposta rifiutata: {lc(label(task))}.", task["id"])


def task_facts(task: dict, inc: dict | None) -> str:
    """Facts for the model's explanation of a proposal (layer-2 data, no network strings)."""
    lines = [f"AZIONE PROPOSTA: {label(task)}", f"EFFETTO: {effect(task)}"]
    if inc:
        c = card(inc)
        lines += [f"ALLARME: {c['title']}", f"COSA È SUCCESSO: {c['what']}", f"PERCHÉ È PERICOLOSO: {c['why']}",
                  f"GRAVITÀ: {inc['severity']}, {inc['level']}"]
    r = task.get("result") if isinstance(task.get("result"), dict) else None
    if r and "connections" in r:
        lines.append("CONTESTO: " + context_text(r))
    return "\n".join(lines)


# ------------------------------------------------------------------ the service
class Agent:
    def __init__(self, store: Store, paths: Paths):
        self.store, self.paths = store, paths

    def level(self) -> str:
        lv = self.store.meta("agent_level", DEFAULT_LEVEL)
        return lv if lv in LEVELS else DEFAULT_LEVEL

    def step(self, now: float | None = None) -> int:
        """One pass: expire, then propose for open incidents. Returns new tasks created."""
        now = now or time.time()
        st = self.store
        st.set_meta("agent_heartbeat", now, commit=True)
        tasks = st.tasks(1000)
        for t in tasks:
            if t["status"] == ATTIVA and t.get("expires_ts") and t["expires_ts"] < now:
                st.update_task(t["id"], status=SCADUTA)
                st.agent_log(f"Scaduto: {lc(label(t))}.", t["id"])
        if st.meta("agent_paused", False):
            return 0
        level = self.level()
        ctx = network_ctx(st)
        own = bool(ctx.get("gateway_mac")) and st.meta("own_network") == ctx.get("gateway_mac")
        busy = {(t["action"], t["target"]) for t in tasks
                if t["status"] in OPEN_STATES or (t["status"] in (RIFIUTATA, COMPLETATA, ANNULLATA, ERRORE)
                                                   and now - t["updated_ts"] < 86400)}
        recent = sum(1 for t in tasks if t["action"] != "context" and now - t["ts"] < 3600)
        created = 0
        for inc in sorted(st.incidents(since=now - LOOKBACK, only_open=True), key=lambda i: i["last_ts"]):
            for s in plan(inc, ctx, own):
                k = (s["action"], s["target"])
                if k in busy:
                    continue
                if s["action"] == "context":
                    tid = st.add_task(inc["key"], "context", s["target"], s["params"], IN_CORSO, s["reason"])
                    r = collect_context(s["target"], self.paths, (inc["first_ts"], inc["last_ts"]))
                    st.update_task(tid, status=COMPLETATA, result=r)
                    st.agent_log(f"Ho raccolto il contesto su {s['target']} per «{card(inc)['title']}». "
                                 + context_text(r), tid)
                else:
                    if recent >= MAX_PER_HOUR:
                        continue
                    status = CONSIGLIO if level == "osserva" else PROPOSTA
                    tid = st.add_task(inc["key"], s["action"], s["target"], s["params"], status, s["reason"])
                    t = {"action": s["action"], "target": s["target"], "params": s["params"]}
                    verb = "Consiglio" if status == CONSIGLIO else "Propongo"
                    st.agent_log(f"Ho notato: {card(inc)['title']}. {verb}: {lc(label(t))}.", tid)
                    recent += 1
                busy.add(k)
                created += 1
        return created

    def run(self, interval: float = 3.0) -> None:
        self.store.agent_log("Agente avviato (livello: " + self.level() + ").")
        while True:
            try:
                self.step()
            except Exception as e:                  # noqa: BLE001 — keep watching
                print("agent:", e, file=sys.stderr)
            time.sleep(interval)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel agent: proposals from alarms (approved in the Security Center)")
    ap.add_argument("--once", action="store_true", help="one pass and exit")
    a = ap.parse_args(argv)
    paths = Paths()
    store = Store(paths.db)
    ag = Agent(store, paths)
    if a.once:
        print(json.dumps({"created": ag.step()}))
        return 0
    ag.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
