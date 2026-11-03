"""Incident report (HTML + JSON) — written for a non-technical reader first,
with the technical evidence in an appendix."""

from __future__ import annotations

import html
import json
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .devices import TYPE_LABEL, guess_type, vendor
from .templates import card

COLOUR_TEXT = {"verde": ("#1e8e3e", "Nessuna attività sospetta importante rilevata"),
               "giallo": ("#b88600", "Attività sospette: verifica consigliata"),
               "rosso": ("#c5221f", "Evento grave confermato: attenzione immediata"),
               "grigio": ("#6b6b6b", "Monitoraggio non attivo o incompleto")}


def _t(ts):
    return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S") if ts else "—"


def build(status: dict, incidents: list[dict], devices: list[dict], actions: list[dict],
          lang: str = "it") -> tuple[str, dict]:
    col, txt = COLOUR_TEXT.get(status.get("colour", "grigio"), COLOUR_TEXT["grigio"])
    e = html.escape
    rows = []
    for i in incidents:
        c = card(i, lang)
        rows.append(f"""<section class="inc"><h3>{e(c['title'])}</h3>
<p class="meta">{e(c['level'])} · urgenza: {e(c['severity'])} · ultimo: {_t(i['last_ts'])} · occorrenze: {i.get('count', 1)}</p>
<p><b>Cosa è successo.</b> {e(c['what'])}</p><p><b>Perché può essere pericoloso.</b> {e(c['why'])}</p>
<p><b>Cosa fare.</b> {e(c['todo'])}</p><p><b>Serve agire subito?</b> {e(c['urgency'])}</p></section>""")
    devs = "".join(
        f"<tr><td>{e(TYPE_LABEL['it'][guess_type(d)])}</td><td>{e(d.get('ip') or '')}</td><td>{e(d.get('mac') or '')}</td>"
        f"<td>{e(vendor(d.get('mac')) or '')}</td><td>{'nuovo' if d.get('new') else ''}</td></tr>" for d in devices)
    acts = "".join(f"<tr><td>{_t(a['ts'])}</td><td>{e(a['action'])}</td><td>{e(a['target'])}</td>"
                   f"<td>{'annullata ' + _t(a['undone_ts']) if a.get('undone_ts') else ''}</td></tr>" for a in actions)
    evid = "".join(f"<tr><td>{e(i['rule'])}</td><td>{e(json.dumps(i['facts'], ensure_ascii=False))}</td>"
                   f"<td>{e(', '.join(i['evidence'][:5]))}</td></tr>" for i in incidents)
    doc = f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8">
<title>Report CyberDistro Sentinel {_t(time.time())}</title>
<style>body{{font-family:DejaVu Sans,Arial,sans-serif;max-width:880px;margin:24px auto;padding:0 16px;color:#202124}}
.st{{border:3px solid {col};border-radius:10px;padding:14px 18px}}.st b{{color:{col};font-size:1.3em}}
.inc{{border-top:1px solid #ddd;padding-top:8px}}.meta{{color:#5f6368;font-size:.9em}}
table{{border-collapse:collapse;width:100%;font-size:.9em}}td,th{{border:1px solid #ddd;padding:4px 6px;text-align:left}}</style></head><body>
<h1>Report di sicurezza della rete</h1>
<p class="meta">CyberDistro Sentinel {__version__} · generato il {_t(time.time())}</p>
<div class="st"><b>{e(status.get('colour', 'grigio').upper())}</b> — {e(txt)}<br>
<span class="meta">Verde non è una garanzia: Sentinel vede solo il traffico che arriva a questo computer.
Le conclusioni vengono dai motori di rilevamento; le spiegazioni dell'assistente non decidono nulla.</span></div>
<h2>Eventi ({len(incidents)})</h2>{''.join(rows) or '<p>Nessun evento registrato.</p>'}
<h2>Dispositivi visti ({len(devices)})</h2><table><tr><th>Tipo (probabile)</th><th>IP</th><th>MAC</th><th>Produttore</th><th></th></tr>{devs}</table>
<h2>Azioni eseguite</h2><table><tr><th>Quando</th><th>Azione</th><th>Obiettivo</th><th></th></tr>{acts or '<tr><td colspan=4>Nessuna</td></tr>'}</table>
<h2>Appendice tecnica: prove</h2><table><tr><th>Regola</th><th>Fatti</th><th>Record (max 5)</th></tr>{evid}</table>
</body></html>"""
    data = {"generated": time.time(), "version": __version__, "status": status,
            "incidents": incidents, "devices": devices, "actions": actions}
    return doc, data


def write(dirpath: Path, status, incidents, devices, actions, lang="it") -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    stem = "sentinel-report-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    doc, data = build(status, incidents, devices, actions, lang)
    (dirpath / f"{stem}.html").write_text(doc, encoding="utf-8")
    (dirpath / f"{stem}.json").write_text(json.dumps(data, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    return dirpath / f"{stem}.html"
