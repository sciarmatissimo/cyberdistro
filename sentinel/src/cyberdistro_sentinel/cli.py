"""sentinel — command line for advanced users (the GUI is the primary interface).

  sentinel status            colour, counters, missing engines
  sentinel incidents [-a]    open incidents (-a: all, with facts)
  sentinel devices           device inventory
  sentinel explain N         card for incident N (as numbered by "incidents")
  sentinel explain-ai N      same incident explained by the local model (verified)
  sentinel ask "domanda"     deterministic answer to a common question
"""

from __future__ import annotations

import argparse
import json
import sys

from .assistant import answer_question
from .config import Paths
from .devices import TYPE_LABEL, guess_type, vendor
from .store import Store
from .templates import card


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    pi = sub.add_parser("incidents")
    pi.add_argument("-a", "--all", action="store_true")
    sub.add_parser("devices")
    pe = sub.add_parser("explain")
    pe.add_argument("n", type=int)
    pa = sub.add_parser("explain-ai", help="incident N explained by the local model (verified)")
    pa.add_argument("n", type=int)
    pq = sub.add_parser("ask")
    pq.add_argument("question")
    a = ap.parse_args(argv)
    paths = Paths()
    try:
        status = json.loads(paths.status_file.read_text())
    except (OSError, ValueError):
        status = {"colour": "grigio", "missing": ["sentinel-core"]}
    store = Store(paths.db) if paths.db.exists() else None
    incs = store.incidents(only_open=False) if store else []
    devs = store.devices() if store else []
    if a.cmd == "status":
        print(json.dumps(status, indent=1, ensure_ascii=False))
    elif a.cmd == "incidents":
        rows = incs if a.all else [i for i in incs if i["status"] == "aperto"]
        for n, i in enumerate(rows, 1):
            print(f"{n:3} [{i['severity']:5}] [{i['level']:10}] {card(i)['title']}  ({i.get('src')} -> {i.get('dst')})")
            if a.all:
                print("      ", json.dumps(i["facts"], ensure_ascii=False))
    elif a.cmd == "devices":
        for d in devs:
            print(f"{d.get('ip') or '-':16} {d.get('mac') or '-':18} {TYPE_LABEL['it'][guess_type(d)]:18} "
                  f"{vendor(d.get('mac')) or ''}{'  NUOVO' if d.get('new') else ''}")
    elif a.cmd == "explain":
        rows = [i for i in incs if i["status"] == "aperto"]
        if not 1 <= a.n <= len(rows):
            print("numero non valido", file=sys.stderr)
            return 2
        c = card(rows[a.n - 1])
        for k in ("title", "level", "what", "why", "todo", "urgency"):
            print(c[k])
        print("Prove:", "; ".join(c["evidence"]))
    elif a.cmd == "explain-ai":
        from .assistant import LLM, explain
        rows = [i for i in incs if i["status"] == "aperto"]
        if not 1 <= a.n <= len(rows):
            print("numero non valido", file=sys.stderr)
            return 2
        llm = LLM(paths)
        try:
            r = explain(rows[a.n - 1], llm)
        finally:
            llm.stop()
        print(json.dumps({"fonte": r["source"], "spiegazione": r["simple"], "problemi": r["problems"]},
                         indent=1, ensure_ascii=False))
    elif a.cmd == "ask":
        print(answer_question(a.question, status, incs, devs) or "Domanda non riconosciuta: usa la sezione Assistente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
