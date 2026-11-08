"""Security Center Sentinel — the main (and only) application of the kiosk.

Sections: Home · Rete · Protezione · Assistente AI · Report · Privacy · Impostazioni.
Beginner mode is the default; Advanced mode adds raw facts, evidence pointers,
engine status and log excerpts. The GUI only READS layer-2 results; it never
decides the status colour. Actions that touch the system go through fixed
helpers via pkexec and always ask for confirmation first.
"""

from __future__ import annotations

import html
import ipaddress
import json
import math
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal, QPointF, QRectF
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QBrush
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFrame,
                               QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QMessageBox, QPushButton, QScrollArea,
                               QSizePolicy, QSplitter, QStackedWidget, QTextBrowser, QVBoxLayout, QWidget)

from .. import __version__
from ..assistant import LLM, answer_free, answer_question, describe_device, explain, last_scan_of, network_facts
from ..knowledge import parse_nmap_open, ports_from_result, summarize_ports
from ..config import Paths
from ..devices import TYPE_LABEL, guess_type, vendor
from ..report import write as write_report
from ..store import Store
from ..templates import card

COLOURS = {"verde": "#1e8e3e", "giallo": "#d29b00", "rosso": "#c5221f", "grigio": "#80868b"}
HEAD = {"verde": "Nessuna attività sospetta importante rilevata",
        "giallo": "Attività sospetta: verifica consigliata",
        "rosso": "Evento grave confermato: serve attenzione subito",
        "grigio": "Monitoraggio non attivo o incompleto"}
SEV_COL = {"alta": "#c5221f", "media": "#d29b00", "bassa": "#5f6368"}
QUICK_QUESTIONS = ["La mia rete è sicura?", "Qualcuno sta cercando di attaccare la mia rete?",
                   "Ci sono dispositivi sconosciuti?", "Hai notato qualcosa di insolito nell'ultima ora?",
                   "Cosa devo fare adesso?", "Spiegami l'ultimo allarme senza termini tecnici",
                   "Cosa hanno trovato i miei esami (porte aperte)?", "Quanti computer ci sono in rete?"]

CSS = """
QWidget { font-family: 'DejaVu Sans'; font-size: 15px; color: #202124; }
QMainWindow, #page { background: #f6f7f9; }
#sidebar { background: #ffffff; border-right: 1px solid #dadce0; font-size: 17px; }
#sidebar::item { padding: 14px 18px; border-radius: 8px; margin: 2px 8px; }
#sidebar::item:selected { background: #e8f0fe; color: #174ea6; font-weight: bold; }
#card { background: #ffffff; border: 1px solid #dadce0; border-radius: 10px; }
#h1 { font-size: 26px; font-weight: bold; }
#h2 { font-size: 19px; font-weight: bold; }
#muted { color: #5f6368; font-size: 14px; }
#big { font-size: 34px; font-weight: bold; }
QPushButton { background: #ffffff; border: 1px solid #c4c7c5; border-radius: 8px; padding: 9px 16px; }
QPushButton:hover { background: #f1f3f4; }
QPushButton#primary { background: #1a73e8; color: white; border: none; font-weight: bold; }
QPushButton#danger { background: #fce8e6; color: #a50e0e; border: 1px solid #f4c7c3; }
QListWidget { background: #ffffff; border: 1px solid #dadce0; border-radius: 8px; }
QTextBrowser, QLineEdit { background: #ffffff; border: 1px solid #dadce0; border-radius: 8px; padding: 6px; }
"""


# ------------------------------------------------------------------ helpers
class _Sig(QObject):
    done = Signal(object)


class Job(QRunnable):
    """Run a function in the thread pool and deliver its result on the GUI thread."""

    def __init__(self, fn, cb):
        super().__init__()
        self.fn, self.sig = fn, _Sig()
        self.sig.done.connect(cb)

    def run(self):
        try:
            res = self.fn()
        except Exception as e:                    # noqa: BLE001 — shown to the user
            res = e
        self.sig.done.emit(res)


def run(cmd, timeout=600) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def when(ts) -> str:
    if not ts:
        return "—"
    d = time.time() - ts
    if d < 90:
        return "adesso"
    if d < 3600:
        m = int(d // 60)
        return "1 minuto fa" if m == 1 else f"{m} minuti fa"
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")


def label(text, obj=None, wrap=True) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    lb.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lb


def cardframe() -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(18, 16, 18, 16)
    return f, lay


def confirm(parent, title, text) -> bool:
    return QMessageBox.question(parent, title, text, QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) == QMessageBox.Yes


# ------------------------------------------------------------------ data
class Data:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.status: dict = {"colour": "grigio", "missing": ["sentinel-core"]}
        self.incidents: list[dict] = []
        self.devices: list[dict] = []
        self.actions: list[dict] = []
        self._store: Store | None = None

    def store(self) -> Store | None:
        if self._store is None and self.paths.db.exists():
            try:
                self._store = Store(self.paths.db)
            except Exception:                      # noqa: BLE001
                self._store = None
        return self._store

    def refresh(self):
        try:
            self.status = json.loads(self.paths.status_file.read_text())
            if time.time() - self.status.get("updated", 0) > 30:
                self.status = {**self.status, "colour": "grigio", "missing": ["sentinel-core (non risponde)"]}
        except (OSError, ValueError):
            self.status = {"colour": "grigio", "missing": ["sentinel-core"]}
        st = self.store()
        if st:
            try:
                self.incidents = st.incidents()
                self.devices = st.devices()
                self.actions = st.actions()
            except Exception:                      # noqa: BLE001 — database busy: keep last data
                pass


def network_info() -> dict:
    code, out = run(["nmcli", "-t", "-f", "TYPE,STATE,CONNECTION,DEVICE", "device"], 5)
    info = {"name": None, "type": None, "device": None}
    if code == 0:
        for line in out.splitlines():
            f = line.split(":")
            if len(f) >= 4 and f[1] == "connected" and f[0] in ("wifi", "ethernet"):
                info.update(name=f[2], type="Wi-Fi" if f[0] == "wifi" else "cavo", device=f[3])
                break
    return info


# ------------------------------------------------------------------ widgets
class StatusDot(QWidget):
    def __init__(self):
        super().__init__()
        self.colour = "grigio"
        self.setFixedSize(132, 132)

    def set(self, colour):
        self.colour = colour
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(COLOURS.get(self.colour, "#80868b")))
        p.setPen(Qt.NoPen)
        p.drawEllipse(6, 6, 120, 120)
        p.setPen(QColor("white"))
        f = QFont("DejaVu Sans", 15, QFont.Bold)
        p.setFont(f)
        p.drawText(QRectF(6, 6, 120, 120), Qt.AlignCenter, self.colour.upper())


class NetworkMap(QWidget):
    """Star map: router in the middle, devices around. Click selects a device."""
    picked = Signal(dict)

    def __init__(self):
        super().__init__()
        self.devices: list[dict] = []
        self.flagged: set[str] = set()
        self.pos: list[tuple[QPointF, dict]] = []
        self.sel: str | None = None
        self.setMinimumSize(520, 420)

    def set(self, devices, flagged):
        self.devices, self.flagged = devices, flagged
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        c = QPointF(w / 2, h / 2)
        gw = [d for d in self.devices if d.get("is_gateway")]
        others = [d for d in self.devices if not d.get("is_gateway")]
        r = min(w, h) / 2 - 70
        self.pos = []
        if gw:
            self.pos.append((c, gw[0]))
        n = max(1, len(others))
        for i, d in enumerate(others):
            a = 2 * math.pi * i / n - math.pi / 2
            self.pos.append((QPointF(c.x() + r * math.cos(a), c.y() + r * math.sin(a)), d))
        p.setPen(QPen(QColor("#c4c7c5"), 1.5))
        for pt, d in self.pos:
            if not d.get("is_gateway"):
                p.drawLine(c, pt)
        short = {"router": "R", "self": "TU", "pc": "PC", "phone": "TEL", "printer": "STA", "tv": "TV",
                 "iot": "IoT", "unknown": "?"}
        for pt, d in self.pos:
            key = d.get("key")
            bad = d.get("ip") in self.flagged or d.get("mac") in self.flagged
            col = "#c5221f" if bad else ("#1a73e8" if d.get("new") else ("#174ea6" if d.get("is_gateway") else "#5f6368"))
            p.setBrush(QBrush(QColor("#ffffff")))
            p.setPen(QPen(QColor(col), 4 if key == self.sel else 2.5))
            rad = 30 if d.get("is_gateway") else 24
            p.drawEllipse(pt, rad, rad)
            kind = guess_type(d)
            p.setPen(QColor("#202124"))
            p.setFont(QFont("DejaVu Sans", 10, QFont.Bold))
            p.drawText(QRectF(pt.x() - rad, pt.y() - 10, 2 * rad, 20), Qt.AlignCenter, short[kind])
            p.setFont(QFont("DejaVu Sans", 9, QFont.Bold))
            p.drawText(QRectF(pt.x() - 110, pt.y() + rad + 2, 220, 16), Qt.AlignCenter, TYPE_LABEL["it"][kind])
            p.setFont(QFont("DejaVu Sans", 9))
            tag = d.get("ip") or d.get("mac") or ""
            if bad:
                tag += " · SOSPETTO"
            elif d.get("new"):
                tag += " · NUOVO"
            p.setPen(QColor(col))
            p.drawText(QRectF(pt.x() - 110, pt.y() + rad + 18, 220, 16), Qt.AlignCenter, tag)
        if not self.devices:
            p.setPen(QColor("#5f6368"))
            p.drawText(self.rect(), Qt.AlignCenter, "Nessun dispositivo visto finora.\nSentinel li scopre ascoltando la rete.")

    def mousePressEvent(self, ev):
        for pt, d in self.pos:
            if (pt - ev.position()).manhattanLength() < 40:
                self.sel = d.get("key")
                self.picked.emit(d)
                self.update()
                return


# ------------------------------------------------------------------ main window
class Main(QMainWindow):
    def __init__(self, paths: Paths | None = None, smoke: bool = False):
        super().__init__()
        self.paths = paths or Paths()
        self.data = Data(self.paths)
        self.llm = LLM(self.paths)
        self.pool = QThreadPool.globalInstance()
        self.advanced = False
        self.lang = "it"
        self.smoke = smoke
        self.selected_inc: dict | None = None
        self.setWindowTitle("Security Center Sentinel")
        root = QWidget()
        self.setCentralWidget(root)
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("sidebar")
        self.nav.setFixedWidth(230)
        self.stack = QStackedWidget()
        lay.addWidget(self.nav)
        lay.addWidget(self.stack, 1)
        self.pages = {}
        for name, build in (("Home", self.page_home), ("Rete", self.page_network),
                            ("Protezione", self.page_protection), ("Assistente AI", self.page_assistant),
                            ("Report", self.page_report), ("Privacy", self.page_privacy),
                            ("Impostazioni", self.page_settings)):
            w = QWidget()
            w.setObjectName("page")
            v = QVBoxLayout(w)
            v.setContentsMargins(28, 24, 28, 24)
            v.setSpacing(14)
            build(v)
            sc = QScrollArea()
            sc.setWidgetResizable(True)
            sc.setFrameShape(QFrame.NoFrame)
            sc.setWidget(w)
            self.stack.addWidget(sc)
            self.nav.addItem(QListWidgetItem(name))
            self.pages[name] = self.stack.count() - 1
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.currentRowChanged.connect(lambda r: r == self.pages.get("Privacy") and self.update_privacy())
        self.nav.setCurrentRow(0)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(3000)
        self.idle = QTimer(self)
        self.idle.timeout.connect(self.llm.stop_if_idle)
        self.idle.start(60000)
        self.refresh()

    def go(self, name):
        self.nav.setCurrentRow(self.pages[name])

    # ---------------------------------------------------------------- Home
    def page_home(self, v):
        f, l = cardframe()
        row = QHBoxLayout()
        self.dot = StatusDot()
        row.addWidget(self.dot)
        col = QVBoxLayout()
        self.h_head = label("", "h1")
        self.h_caveat = label("Verde vuol dire che non abbiamo rilevato nulla di grave: non è una garanzia di sicurezza.", "muted")
        self.h_scope = label("Sentinel ascolta in modo passivo e vede solo il traffico che arriva a questo computer, "
                             "non quello tra gli altri dispositivi.", "muted")
        self.h_net = label("", "muted")
        for x in (self.h_head, self.h_caveat, self.h_scope, self.h_net):
            col.addWidget(x)
        row.addLayout(col, 1)
        l.addLayout(row)
        v.addWidget(f)
        grid = QGridLayout()
        self.tiles = {}
        for i, (k, t) in enumerate((("dev", "Dispositivi connessi"), ("alerts", "Allarmi da guardare"),
                                    ("last", "Ultima attività sospetta"))):
            tf, tl = cardframe()
            tl.addWidget(label(t, "muted"))
            val = label("—", "big")
            tl.addWidget(val)
            self.tiles[k] = val
            grid.addWidget(tf, 0, i)
        v.addLayout(grid)
        af, al = cardframe()
        al.addWidget(label("Riepilogo dell'assistente", "h2"))
        self.h_summary = label("", None)
        al.addWidget(self.h_summary)
        v.addWidget(af)
        btns = QHBoxLayout()
        for text, fn, obj in (("Connetti a una rete", self.wifi_dialog, "primary"),
                              ("Vedi gli allarmi", lambda: self.go("Protezione"), None),
                              ("Esamina la rete (attivo)", self.active_scan, None),
                              ("Genera report", self.make_report, None)):
            b = QPushButton(text)
            if obj:
                b.setObjectName(obj)
            b.clicked.connect(fn)
            btns.addWidget(b)
        btns.addStretch()
        v.addLayout(btns)
        v.addStretch()

    def update_home(self):
        st = self.data.status
        colour = st.get("colour", "grigio")
        self.dot.set(colour)
        self.h_head.setText(HEAD.get(colour, HEAD["grigio"]))
        net = network_info()
        if net["name"]:
            self.h_net.setText(f"Connesso a «{net['name']}» via {net['type']} · monitoraggio "
                               + ("attivo" if colour != "grigio" else "incompleto"))
        else:
            self.h_net.setText("Non sei connesso a nessuna rete. Usa «Connetti a una rete».")
        if colour == "grigio" and st.get("missing"):
            self.h_net.setText(self.h_net.text() + " · manca: " + ", ".join(st["missing"]))
        open_ = [i for i in self.data.incidents if i.get("status") == "aperto" and i["severity"] != "bassa"]
        self.tiles["dev"].setText(str(len(self.data.devices)))
        self.tiles["alerts"].setText(str(len(open_)))
        self.tiles["last"].setText(when(st.get("last")) if st.get("last") else "nessuna")
        self.h_summary.setText(answer_question("La mia rete è sicura?", st, self.data.incidents, self.data.devices,
                                               actions=self.data.actions)
                               + ("\n" + answer_question("Ci sono dispositivi sconosciuti?", st,
                                                          self.data.incidents, self.data.devices)))

    # ---------------------------------------------------------------- Rete
    def page_network(self, v):
        v.addWidget(label("La tua rete", "h1"))
        v.addWidget(label("Router al centro, dispositivi intorno. Blu = nuovo, rosso = coinvolto in un allarme. "
                          "Il tipo di dispositivo è una stima.", "muted"))
        sp = QSplitter()
        self.map = NetworkMap()
        self.map.picked.connect(self.show_device)
        sp.addWidget(self.map)
        df, dl = cardframe()
        self.dev_info = QTextBrowser()
        self.dev_info.setOpenExternalLinks(False)
        self.dev_info.setHtml("<p>Seleziona un dispositivo sulla mappa.</p>")
        dl.addWidget(self.dev_info)
        b1 = QPushButton("Esamina questo dispositivo (Nmap)")
        b1.clicked.connect(lambda: self.scan_device())
        b2 = QPushButton("Blocca su questo PC")
        self.b_dev_block = b2
        b2.setObjectName("danger")
        b2.clicked.connect(lambda: self.block(self.sel_dev.get("ip") if self.sel_dev else None))
        dl.addWidget(b1)
        dl.addWidget(b2)
        sp.addWidget(df)
        sp.setSizes([600, 380])
        v.addWidget(sp, 1)
        self.sel_dev: dict | None = None

    def update_network(self):
        flagged = {i.get("src") for i in self.data.incidents if i["severity"] != "bassa"} - {None}
        flagged |= {i["facts"].get("new_mac") for i in self.data.incidents if i["rule"] == "arp_spoof"} - {None}
        self.map.set(self.data.devices, flagged)

    def show_device(self, d):
        self.sel_dev = d
        e = html.escape
        rel = [i for i in self.data.incidents if d.get("ip") in (i.get("src"), i.get("dst"))]
        names = ", ".join(([d["hostname"]] if d.get("hostname") else []) + list(d.get("mdns") or [])) or "non annunciato"
        txt = (f"<h3>{e(TYPE_LABEL['it'][guess_type(d)])} (probabile)</h3>"
               f"<p><b>Indirizzo IP:</b> {e(d.get('ip') or '—')}<br><b>Scheda di rete (MAC):</b> {e(d.get('mac') or '—')}"
               f"<br><b>Produttore:</b> {e(vendor(d.get('mac')) or 'sconosciuto')}<br><b>Nome annunciato:</b> {e(names)}"
               f"<br><b>Visto la prima volta:</b> {when(d.get('first_seen'))}<br><b>Ultima volta:</b> {when(d.get('last_seen'))}</p>")
        if d.get("new"):
            txt += "<p>È comparso dopo l'avvio del monitoraggio.</p>"
        txt += f"<p><b>Allarmi che lo riguardano:</b> {len(rel)}</p><ul>"
        for i in rel[:8]:
            txt += f"<li>{e(card(i)['title'])} ({e(i['severity'])})</li>"
        txt += "</ul>"
        sc = last_scan_of(d.get("ip"), self.data.actions) if d.get("ip") else None
        if sc:
            txt += f"<p><b>Ultimo esame ({when(sc['ts'])}):</b></p><p>" + e(
                summarize_ports(ports_from_result(sc.get("result", "")))).replace("\n", "<br>") + "</p>"
        if self.advanced and d.get("services"):
            txt += "<p><b>Servizi mDNS:</b> " + e(", ".join(d["services"])) + "</p>"
        self.dev_info.setHtml(txt)
        role = "self" if d.get("is_self") else "gateway" if d.get("is_gateway") else None
        self.b_dev_block.setEnabled(role is None)
        self.b_dev_block.setToolTip({"self": "È questo PC.", "gateway": "È il router: bloccarlo interromperebbe "
                                     "la connessione."}.get(role, ""))

    # ---------------------------------------------------------------- Protezione
    def page_protection(self, v):
        v.addWidget(label("Protezione", "h1"))
        self.p_engines = label("", "muted")
        v.addWidget(self.p_engines)
        sp = QSplitter()
        self.inc_list = QListWidget()
        self.inc_list.setWordWrap(True)
        self.inc_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.inc_list.currentRowChanged.connect(self.show_incident)
        sp.addWidget(self.inc_list)
        cf, cl = cardframe()
        self.inc_view = QTextBrowser()
        cl.addWidget(self.inc_view, 1)
        row = QHBoxLayout()
        self.b_ai = QPushButton("Spiegazione semplice (AI)")
        self.b_ai.clicked.connect(self.ai_explain)
        self.b_block = QPushButton("Blocca l'origine su questo PC")
        self.b_block.setObjectName("danger")
        self.b_block.clicked.connect(lambda: self.block(self.selected_inc.get("src") if self.selected_inc else None))
        self.b_close = QPushButton("Segna come gestito")
        self.b_close.clicked.connect(self.close_incident)
        for b in (self.b_ai, self.b_block, self.b_close):
            row.addWidget(b)
        cl.addLayout(row)
        sp.addWidget(cf)
        sp.setSizes([420, 580])
        v.addWidget(sp, 1)

    def update_protection(self):
        st = self.data.status
        self.p_engines.setText("Motori: Suricata (firme), Zeek (protocolli), sensore passivo (ARP/DHCP/mDNS). "
                               + ("Tutti attivi." if not st.get("missing") else "Non attivi: " + ", ".join(st["missing"])))
        keep = self.selected_inc.get("key") if self.selected_inc else None
        self.inc_list.blockSignals(True)
        self.inc_list.clear()
        rows = [i for i in self.data.incidents if self.advanced or i["severity"] != "bassa"
                or i["rule"] in ("new_device", "own_scan")]
        news = [i for i in rows if i["rule"] == "new_device"]
        if len(news) > 2:                       # one row for many "new device" events
            g = {"key": "group:new_device", "rule": "group_new_device", "severity": "bassa", "level": "confermato",
                 "last_ts": max(i["last_ts"] for i in news), "status": "aperto", "items": news, "facts": {},
                 "src": None, "dst": None, "evidence": []}
            first = rows.index(news[0])
            rows = [i for i in rows if i["rule"] != "new_device"]
            rows.insert(min(first, len(rows)), g)
        self._inc_rows = rows
        sel = -1
        for n, i in enumerate(self._inc_rows):
            if i["rule"] == "group_new_device":
                byscan = sum(1 for x in i["items"] if x["facts"].get("found_by_scan"))
                c = {"title": f"{len(i['items'])} dispositivi nuovi in rete"
                              + (f" ({byscan} trovati dalla tua scansione)" if byscan else "")}
            else:
                c = card(i)
            it = QListWidgetItem(f"● {c['title']}\n{when(i['last_ts'])} · {i['level']}"
                                 + ("" if i.get("status") == "aperto" else " · gestito"))
            it.setForeground(QColor(SEV_COL[i["severity"]]))
            self.inc_list.addItem(it)
            if i["key"] == keep:
                sel = n
        if sel < 0 and self._inc_rows:
            sel = 0                                 # beginners: show the most recent alert
        if sel >= 0:
            self.inc_list.setCurrentRow(sel)        # restore without re-rendering the card
        self.inc_list.blockSignals(False)
        if sel >= 0 and self._inc_rows[sel]["key"] != getattr(self, "_shown_key", None):
            self.show_incident(sel)
        if not self._inc_rows:
            self.selected_inc = None
            self._shown_key = None
        if not self._inc_rows:
            self.inc_view.setHtml("<h3>Nessun allarme</h3><p>Quando Sentinel rileva qualcosa, lo trovi qui "
                                  "spiegato in parole semplici.</p>")

    def show_incident(self, row):
        if row < 0 or row >= len(getattr(self, "_inc_rows", [])):
            return
        i = self._inc_rows[row]
        self.selected_inc = i
        self._shown_key = i["key"]
        if i.get("rule") == "group_new_device":
            self.show_group(i)
            return
        c = card(i)
        e = html.escape
        f = i.get("facts", {})
        can_block = (i.get("src") and f.get("src_role") not in ("self", "gateway") and i["severity"] != "bassa"
                     and i["rule"] != "own_scan")
        self.b_block.setEnabled(bool(can_block))
        self.b_block.setToolTip("" if can_block else "Non c'è un'origine da bloccare: è questo PC, il router "
                                "oppure un evento solo informativo.")
        h = (f"<h2 style='color:{SEV_COL[i['severity']]}'>{e(c['title'])}</h2>"
             f"<p><i>{e(c['level'])}</i></p>"
             f"<h4>1. Cosa è successo</h4><p>{e(c['what'])}</p>"
             f"<h4>2. Perché può essere pericoloso</h4><p>{e(c['why'])}</p>"
             f"<h4>3. Le prove</h4><ul>" + "".join(f"<li>{e(x)}</li>" for x in c["evidence"]) + "</ul>"
             f"<h4>4. Cosa fare</h4><p>{e(c['todo'])}</p>"
             f"<h4>5. Serve agire subito?</h4><p>{e(c['urgency'])}</p>")
        if self.advanced:
            h += ("<hr><h4>Dettagli tecnici</h4><pre>" + e(json.dumps(
                {"regola": i["rule"], "origine": i.get("src"), "destinazione": i.get("dst"),
                 "fatti": i["facts"], "prove": i["evidence"], "occorrenze": i.get("count"),
                 "prima": datetime.fromtimestamp(i["first_ts"]).isoformat(timespec="seconds"),
                 "ultima": datetime.fromtimestamp(i["last_ts"]).isoformat(timespec="seconds")},
                indent=1, ensure_ascii=False)) + "</pre>")
        self.inc_view.setHtml(h)

    def show_group(self, g):
        e = html.escape
        self.b_block.setEnabled(False)
        h = ("<h2>Dispositivi comparsi dopo l'avvio</h2><p>Sono dispositivi che Sentinel ha sentito per la prima "
             "volta dopo i primi minuti di monitoraggio. Quelli «trovati dalla tua scansione» erano quasi certamente "
             "già in rete: hanno solo risposto all'esame. Se non riconosci un dispositivo, cambia la password del "
             "Wi-Fi del router.</p><ul>")
        devs = {d.get("ip"): d for d in self.data.devices}
        for i in g["items"]:
            ip = i["facts"].get("ip") or "?"
            d = devs.get(ip)
            desc = describe_device(d, self.data.incidents, self.data.actions) if d else ip
            h += f"<li>{e(desc)}" + (" — <i>trovato dalla tua scansione</i>" if i["facts"].get("found_by_scan") else "") + "</li>"
        self.inc_view.setHtml(h + "</ul>")

    def ai_explain(self):
        if not self.selected_inc:
            return
        ok, why = self.llm.availability()
        if not ok:
            QMessageBox.information(self, "Assistente non disponibile",
                                    f"L'assistente AI non può partire: {why}.\nLa scheda qui sopra è comunque completa.")
            return
        inc = dict(self.selected_inc)
        self.b_ai.setEnabled(False)
        self.b_ai.setText("Sto preparando la spiegazione…")

        def done(res):
            self.b_ai.setEnabled(True)
            self.b_ai.setText("Spiegazione semplice (AI)")
            if isinstance(res, Exception):
                QMessageBox.warning(self, "Assistente", str(res))
                return
            if res["source"] != "modello":
                QMessageBox.information(self, "Assistente",
                                        "La spiegazione dell'assistente non ha superato i controlli "
                                        "(conteneva informazioni non presenti nelle prove), quindi non la mostro.\n\n"
                                        + ("Motivo: " + res["problems"][0] if res["problems"] else ""))
                return
            s = res["simple"]
            e = html.escape
            self.inc_view.append(f"<hr><h3>Spiegazione semplice (assistente AI, verificata)</h3>"
                                 f"<p><b>Cosa è successo:</b> {e(s['cosa_successo'])}</p>"
                                 f"<p><b>Perché è pericoloso:</b> {e(s['perche_pericoloso'])}</p>"
                                 f"<p><b>Cosa fare:</b> {e(s['cosa_fare'])}</p>"
                                 "<p><i>Il colore e l'urgenza vengono dal motore di rilevamento, non dall'assistente.</i></p>")
        self.pool.start(Job(lambda: explain(inc, self.llm, self.lang), done))

    def close_incident(self):
        st = self.data.store()
        if self.selected_inc and st:
            st.close_incident(self.selected_inc["key"])
            self.refresh()

    # ---------------------------------------------------------------- Assistente
    def page_assistant(self, v):
        v.addWidget(label("Assistente di sicurezza", "h1"))
        v.addWidget(label("Risponde usando solo ciò che Sentinel ha rilevato. Le risposte rapide funzionano sempre; "
                          "le domande libere usano il modello AI locale (Qwen3.5-2B), che gira su questo PC senza internet.",
                          "muted"))
        self.chat = QTextBrowser()
        self.chat.setMinimumHeight(320)
        v.addWidget(self.chat, 1)
        g = QGridLayout()
        for n, q in enumerate(QUICK_QUESTIONS):
            b = QPushButton(q)
            b.clicked.connect(lambda _=False, q=q: self.ask(q))
            g.addWidget(b, n // 2, n % 2)
        v.addLayout(g)
        row = QHBoxLayout()
        self.q_in = QLineEdit()
        self.q_in.setPlaceholderText("Scrivi una domanda sulla tua rete…")
        self.q_in.returnPressed.connect(lambda: self.ask(self.q_in.text()))
        b = QPushButton("Chiedi")
        b.setObjectName("primary")
        b.clicked.connect(lambda: self.ask(self.q_in.text()))
        row.addWidget(self.q_in, 1)
        row.addWidget(b)
        v.addLayout(row)
        self.ai_state = label("", "muted")
        v.addWidget(self.ai_state)

    def say(self, who, text):
        e = html.escape
        col = "#174ea6" if who == "Tu" else "#202124"
        self.chat.append(f"<p><b style='color:{col}'>{e(who)}:</b> " + e(text).replace("\n", "<br>") + "</p>")

    def ask(self, q):
        q = (q or "").strip()
        if not q:
            return
        self.q_in.clear()
        self.say("Tu", q)
        d = self.data
        if q.startswith("Spiegami l'ultimo allarme"):
            open_ = [i for i in d.incidents if i["severity"] != "bassa"]
            if not open_:
                self.say("Sentinel", "Non ci sono allarmi da spiegare.")
                return
            c = card(open_[0])
            self.say("Sentinel", f"{c['what']} {c['why']} Cosa fare: {c['todo']} {c['urgency']}")
            self.selected_inc = open_[0]
            return
        ans = answer_question(q, d.status, d.incidents, d.devices, actions=d.actions)
        if ans:
            self.say("Sentinel", ans)
            return
        ok, why = self.llm.availability()
        if not ok:
            self.say("Sentinel", f"Per le domande libere serve l'assistente AI, che ora non è disponibile ({why}). "
                                 "Prova una delle domande rapide.")
            return
        self.ai_state.setText("L'assistente sta pensando (su un PC a 2 core può servire mezzo minuto)…")
        facts = network_facts(d.status, d.incidents, d.devices, d.actions)

        def done(res):
            self.ai_state.setText("")
            if isinstance(res, Exception):
                self.say("Sentinel", f"Errore dell'assistente: {res}")
                return
            text, probs = res
            if text:
                self.say("Assistente AI", text)
            else:
                self.say("Sentinel", "Non posso rispondere con certezza a questa domanda con le prove che ho. "
                                     + answer_question("La mia rete è sicura?", d.status, d.incidents, d.devices))
                if probs:                       # say why, so the user (and we) can tell what went wrong
                    self.ai_state.setText("Risposta del modello scartata: " + probs[0][:160])
        self.pool.start(Job(lambda: answer_free(q, facts, self.llm, self.lang), done))

    # ---------------------------------------------------------------- Report
    def page_report(self, v):
        v.addWidget(label("Report", "h1"))
        v.addWidget(label("Il report contiene stato, eventi spiegati in parole semplici, dispositivi visti e azioni "
                          "eseguite, con un'appendice tecnica. In modalità Live va esportato su una chiavetta, "
                          "altrimenti si perde allo spegnimento.", "muted"))
        row = QHBoxLayout()
        b = QPushButton("Genera report")
        b.setObjectName("primary")
        b.clicked.connect(self.make_report)
        b2 = QPushButton("Esporta su chiavetta USB")
        b2.clicked.connect(self.export_report)
        row.addWidget(b)
        row.addWidget(b2)
        row.addStretch()
        v.addLayout(row)
        self.r_info = label("", "muted")
        v.addWidget(self.r_info)
        v.addWidget(label("Azioni eseguite (si possono annullare)", "h2"))
        self.act_list = QListWidget()
        v.addWidget(self.act_list)
        b3 = QPushButton("Annulla l'azione selezionata")
        b3.clicked.connect(self.undo_action)
        v.addWidget(b3)
        v.addStretch()
        self.last_report: Path | None = None

    def update_report(self):
        self.act_list.clear()
        for a in self.data.actions:
            self.act_list.addItem(f"{when(a['ts'])} · {a['action']} {a['target']}"
                                  + (" · annullata" if a.get("undone_ts") else ""))

    def make_report(self):
        out = Path.home() / "Report"
        try:
            p = write_report(out, self.data.status, self.data.incidents, self.data.devices, self.data.actions, self.lang)
        except OSError as e:
            QMessageBox.warning(self, "Report", str(e))
            return
        self.last_report = p
        self.r_info.setText(f"Report salvato: {p}  (e la versione JSON accanto)")
        if not self.smoke:
            QMessageBox.information(self, "Report", f"Report salvato in {p}.")

    def export_report(self):
        if not self.last_report:
            self.make_report()
        code, out = run(["lsblk", "-J", "-o", "NAME,RM,TYPE,MOUNTPOINT,LABEL,SIZE"], 10)
        targets = []
        if code == 0:
            for dev in json.loads(out).get("blockdevices", []):
                for part in dev.get("children", []) or [dev]:
                    if (dev.get("rm") in (True, "1")) and part.get("type") == "part":
                        targets.append(part)
        targets = [t for t in targets if t.get("mountpoint") not in ("/run/live/medium", "/run/live/persistence")]
        if not targets:
            QMessageBox.information(self, "Esporta", "Nessuna chiavetta trovata. Inseriscine una e riprova.")
            return
        names = [f"{t['name']} {t.get('label') or ''} ({t.get('size')})" for t in targets]
        sel, ok = QInputDialog.getItem(self, "Esporta", "Scegli la chiavetta:", names, 0, False)
        if not ok:
            return
        t = targets[names.index(sel)]
        mp = t.get("mountpoint")
        if not mp:
            code, out = run(["udisksctl", "mount", "-b", f"/dev/{t['name']}"], 30)
            if code != 0:
                QMessageBox.warning(self, "Esporta", out)
                return
            mp = out.split(" at ")[-1].strip().rstrip(".")
        dst = Path(mp) / "Sentinel-report"
        dst.mkdir(exist_ok=True)
        for f in (self.last_report, self.last_report.with_suffix(".json")):
            shutil.copy2(f, dst / f.name)
        run(["sync"], 30)
        QMessageBox.information(self, "Esporta", f"Report copiato in {dst}.")

    # ---------------------------------------------------------------- actions
    def block(self, ip):
        if not ip:
            QMessageBox.information(self, "Blocca", "Nessun indirizzo da bloccare.")
            return
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return
        if a.version != 4:
            QMessageBox.information(self, "Blocca", "Per ora si possono bloccare solo indirizzi IPv4.")
            return
        if not confirm(self, "Bloccare questo indirizzo?",
                       f"Questo computer smetterà di comunicare con {ip} per 24 ore.\n\n"
                       "Non cambia nulla sul router o sugli altri dispositivi. Se {ip} è un dispositivo che usi, "
                       "qualcosa potrebbe smettere di funzionare.\nPuoi annullare dalla sezione Report.".replace("{ip}", ip)):
            return
        code, out = run(["pkexec", "/usr/local/sbin/sentinel-action", "block", ip, "24"], 60)
        st = self.data.store()
        if st:
            st.log_action("blocco 24 ore", ip, out[:200] if code == 0 else "errore: " + out[:200])
        QMessageBox.information(self, "Blocca", out or ("Fatto." if code == 0 else "Non riuscito."))
        self.refresh()

    def undo_action(self):
        row = self.act_list.currentRow()
        if row < 0 or row >= len(self.data.actions):
            return
        a = self.data.actions[row]
        if a.get("undone_ts") or not a["action"].startswith("blocco"):
            return
        if not confirm(self, "Annullare?", f"Sbloccare {a['target']}?"):
            return
        code, out = run(["pkexec", "/usr/local/sbin/sentinel-action", "unblock", a["target"]], 60)
        if code == 0 and self.data.store():
            self.data.store().mark_undone(a["id"])
        QMessageBox.information(self, "Annulla", out)
        self.refresh()

    def active_scan(self):
        net = network_info()
        if not net["device"]:
            QMessageBox.information(self, "Esamina", "Non sei connesso a nessuna rete.")
            return
        code, out = run(["ip", "-4", "-o", "addr", "show", "dev", net["device"]], 5)
        try:
            cidr = out.split()[3]
            netw = ipaddress.ip_network(cidr, strict=False)
        except (IndexError, ValueError):
            return
        if netw.num_addresses > 1024:
            netw = ipaddress.ip_network(f"{cidr.split('/')[0]}/24", strict=False)
        if not confirm(self, "Scansione attiva",
                       f"Sentinel invierà pacchetti a tutti gli indirizzi di {netw} per trovare i dispositivi "
                       "che non parlano da soli.\n\nFallo SOLO su una rete tua o su cui hai il permesso. "
                       "È una scansione leggera (nessun attacco), ma alcune reti la segnalano come sospetta.\n\n"
                       "Confermi di avere il permesso?"):
            return
        self.say_status(f"Scansione di {netw} in corso…")
        st = self.data.store()
        aid = st.log_action("scansione rete", str(netw), "in corso") if st else None

        def done(res):
            code, out = res if not isinstance(res, Exception) else (1, str(res))
            n = out.count("Host is up")
            if st and aid:
                st.finish_action(aid, f"dispositivi che hanno risposto: {n}")
            QMessageBox.information(self, "Esamina", f"Dispositivi che hanno risposto: {n}.\n"
                                    "Compariranno nella mappa man mano che Sentinel li sente in rete.\n\n"
                                    "Sentinel registra questa scansione come attività tua, non come attacco.")
            self.refresh()
        self.pool.start(Job(lambda: run(["nmap", "-sn", "-T3", str(netw)], 600), done))

    def scan_device(self):
        d = self.sel_dev
        if not d or not d.get("ip") or ":" in d["ip"]:
            return
        if not confirm(self, "Esaminare il dispositivo?",
                       f"Sentinel controllerà le 100 porte più comuni di {d['ip']}.\n"
                       "Fallo SOLO se il dispositivo è tuo o hai il permesso. Confermi?"):
            return

        st = self.data.store()
        aid = st.log_action("scansione dispositivo", d["ip"], "in corso") if st else None
        self.say_status(f"Esame di {d['ip']} in corso…")

        def done(res):
            code, out = res if not isinstance(res, Exception) else (1, str(res))
            ports = parse_nmap_open(out)
            ok = code == 0 and "Nmap done" in out
            result = (("porte aperte: " + ", ".join(map(str, ports))) if ports else "nessuna porta comune aperta") \
                if ok else "esame non riuscito"
            if st and aid:
                st.finish_action(aid, result)
            if not ok:
                msg = "L'esame non è riuscito.\n" + out[-400:]
            else:
                msg = summarize_ports(ports)
                msg += ("\n\nSentinel ha controllato le 100 porte più comuni. Questa scansione è registrata come "
                        "attività tua: non comparirà come attacco.")
            if self.advanced:
                msg += "\n\nComando: nmap -sT -F -T3 " + d["ip"]
            QMessageBox.information(self, f"Risultato per {d['ip']}", msg)
            self.refresh()
            if self.sel_dev and self.sel_dev.get("ip") == d["ip"]:
                self.show_device(self.sel_dev)
        self.pool.start(Job(lambda: run(["nmap", "-sT", "-F", "-T3", d["ip"]], 600), done))

    def say_status(self, text):
        self.h_net.setText(text)

    def wifi_dialog(self):
        code, out = run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "--rescan", "yes"], 30)
        nets = []
        for line in out.splitlines() if code == 0 else []:
            parts = line.rsplit(":", 2)
            if len(parts) == 3 and parts[0]:
                nets.append(parts)
        if not nets:
            QMessageBox.information(self, "Wi-Fi", "Nessuna rete Wi-Fi trovata. Se usi il cavo, la connessione è automatica.")
            return
        dlg = WifiDialog(nets, self)
        if dlg.exec() != QDialog.Accepted or dlg.choice() is None:
            return
        ssid, sec, pw = dlg.choice()
        cmd = ["nmcli", "device", "wifi", "connect", ssid]
        if sec:
            cmd += ["password", pw]
        code, out = run(cmd, 60)
        QMessageBox.information(self, "Wi-Fi", "Connesso." if code == 0 else f"Connessione non riuscita.\n{out}")

    # ---------------------------------------------------------------- Privacy
    def page_privacy(self, v):
        v.addWidget(label("Privacy e navigazione anonima", "h1"))
        v.addWidget(label("CyberDistro Sentinel non include Tor: puoi installarlo da qui. Finché Tor non è installato "
                          "e il profilo Tor non è attivo, la navigazione NON è anonima.", None))
        warn, wl = cardframe()
        wl.addWidget(label("Prima di installare", "h2"))
        wl.addWidget(label("• In modalità Live, Tor e Tor Browser vengono installati in memoria e spariscono allo spegnimento "
                           "(Tor Browser occupa circa 350 MB di RAM). Con la persistenza cifrata restano.\n"
                           "• Serve internet. Il download avviene prima che Tor sia attivo: chi osserva la rete vede che "
                           "questo computer contatta i server Debian e del Tor Project.\n"
                           "• Il profilo Tor blocca tutto il traffico che non passa da Tor (kill-switch).", None))
        v.addWidget(warn)
        self.pv_state = label("", "h2")
        v.addWidget(self.pv_state)
        g = QGridLayout()
        for n, (t, fn) in enumerate((("1. Installa Tor", lambda: self.priv(["sentinel-install-tor", "tor"], True)),
                                     ("2. Installa Tor Browser", lambda: self.priv(["sentinel-install-tor", "browser"], True)),
                                     ("3. Attiva profilo Tor (anonimo)", lambda: self.priv(["sentinel-privacy", "tor"])),
                                     ("Torna al profilo standard", lambda: self.priv(["sentinel-privacy", "standard"])),
                                     ("Apri Tor Browser", self.open_tbb))):
            b = QPushButton(t)
            b.clicked.connect(fn)
            g.addWidget(b, n // 2, n % 2)
        v.addLayout(g)
        self.pv_out = QTextBrowser()
        self.pv_out.setMaximumHeight(180)
        v.addWidget(self.pv_out)
        v.addStretch()

    def update_privacy(self):
        code, out = run(["/usr/local/sbin/sentinel-install-tor", "status"], 5)
        kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l) if code == 0 else {}
        anon = kv.get("killswitch") == "attivo" and kv.get("tor_attivo") == "active"
        self.pv_state.setText(("Navigazione ANONIMA attiva (Tor + kill-switch)" if anon else
                               "Navigazione NON anonima") +
                              f" · Tor: {kv.get('tor', '?')} · Tor Browser: {kv.get('tor_browser', '?')}")

    def priv(self, cmd, install=False):
        if install and not confirm(self, "Installare?", "Leggi le avvertenze sopra. Procedo con l'installazione?"):
            return
        self.pv_out.setPlainText("In corso… (può richiedere qualche minuto)")

        def done(res):
            code, out = res if not isinstance(res, Exception) else (1, str(res))
            self.pv_out.setPlainText(out[-3000:] or ("Fatto." if code == 0 else "Non riuscito."))
            self.update_privacy()
        self.pool.start(Job(lambda: run(["pkexec", "/usr/local/sbin/" + cmd[0]] + cmd[1:], 1800), done))

    def open_tbb(self):
        exe = Path("/opt/tor-browser/Browser/start-tor-browser")
        if not exe.exists():
            QMessageBox.information(self, "Tor Browser", "Tor Browser non è installato.")
            return
        subprocess.Popen([str(exe), "--detach"], cwd=str(exe.parent))

    # ---------------------------------------------------------------- Impostazioni
    def page_settings(self, v):
        v.addWidget(label("Impostazioni", "h1"))
        self.cb_adv = QCheckBox("Modalità Avanzata (mostra dettagli tecnici, prove e stato dei motori)")
        self.cb_adv.toggled.connect(self.set_advanced)
        v.addWidget(self.cb_adv)
        f, l = cardframe()
        l.addWidget(label("Assistente AI", "h2"))
        self.s_ai = label("", None)
        l.addWidget(self.s_ai)
        v.addWidget(f)
        f2, l2 = cardframe()
        l2.addWidget(label("Salvare i dati sulla chiavetta (persistenza cifrata)", "h2"))
        l2.addWidget(label("Per conservare allarmi, report e programmi installati tra un riavvio e l'altro, crea la "
                           "persistenza cifrata da un terminale (menu con clic destro sul desktop → Terminale):\n"
                           "sudo cyberdistro-make-persistence\n"
                           "Poi riavvia e scegli la voce di avvio con persistenza. La passphrase non si recupera.", None))
        v.addWidget(f2)
        f3, l3 = cardframe()
        l3.addWidget(label("Informazioni", "h2"))
        l3.addWidget(label(f"CyberDistro Sentinel Q3_K_M · Security Center {__version__}\n"
                           "Motori: Suricata 7 (regole Emerging Threats Open ridotte), Zeek 9.0, sensore passivo Sentinel.\n"
                           "Modello: Qwen3.5-2B, quantizzazione Q3_K_M (Apache-2.0), eseguito in locale con llama.cpp.\n"
                           "Nessun servizio cloud. Nessuna telemetria.", "muted"))
        v.addWidget(f3)
        row = QHBoxLayout()
        for t, cmd in (("Riavvia", ["systemctl", "reboot"]), ("Spegni", ["systemctl", "poweroff"])):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, c=cmd, t=t: confirm(self, t, f"{t} il computer?") and run(c, 10))
            row.addWidget(b)
        row.addStretch()
        v.addLayout(row)
        v.addStretch()

    def set_advanced(self, on):
        self.advanced = on
        self.refresh()
        if self.selected_inc:
            self.update_protection()

    def update_settings(self):
        ok, why = self.llm.availability()
        self.s_ai.setText(("Disponibile" if ok else "Non disponibile") + f": {why}. Il modello si avvia solo quando "
                          "chiedi una spiegazione e si chiude dopo 10 minuti senza uso.")

    # ---------------------------------------------------------------- refresh
    def refresh(self):
        self.data.refresh()
        for fn in (self.update_home, self.update_network, self.update_protection, self.update_report,
                   self.update_settings):
            try:
                fn()
            except Exception as e:                 # noqa: BLE001 — never crash the kiosk
                print("refresh:", fn.__name__, e, file=sys.stderr)
        if self.stack.currentIndex() == self.pages.get("Privacy"):
            self.update_privacy()

    def closeEvent(self, ev):
        self.llm.stop()
        super().closeEvent(ev)



class WifiDialog(QDialog):
    """Wi-Fi picker: a normal-sized dialog with Italian buttons and no emoji
    (the kiosk font has no emoji glyphs; QInputDialog showed English buttons)."""

    def __init__(self, nets, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connetti a una rete Wi-Fi")
        self.setMinimumSize(460, 380)
        self.nets = [(s, sig, bool(sec and sec != "--")) for s, sig, sec in nets]
        v = QVBoxLayout(self)
        v.addWidget(QLabel("Scegli la rete:"))
        self.lst = QListWidget()
        for s, sig, sec in self.nets:
            self.lst.addItem(QListWidgetItem(f"{s}    segnale {sig}%    {'protetta' if sec else 'aperta'}"))
        self.lst.setCurrentRow(0)
        v.addWidget(self.lst, 1)
        self.pwl = QLabel("Password:")
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        v.addWidget(self.pwl)
        v.addWidget(self.pw)
        self.show_pw = QCheckBox("Mostra la password")
        self.show_pw.toggled.connect(lambda on: self.pw.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        v.addWidget(self.show_pw)
        bb = QDialogButtonBox()
        self.ok = bb.addButton("Connetti", QDialogButtonBox.AcceptRole)
        bb.addButton("Annulla", QDialogButtonBox.RejectRole)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)
        self.lst.currentRowChanged.connect(self._sync)
        self.lst.itemDoubleClicked.connect(lambda _i: self.accept())
        self._sync()

    def _sync(self, *_):
        row = self.lst.currentRow()
        sec = row >= 0 and self.nets[row][2]
        for w in (self.pwl, self.pw, self.show_pw):
            w.setVisible(bool(sec))

    def choice(self):
        row = self.lst.currentRow()
        if row < 0:
            return None
        s, _sig, sec = self.nets[row]
        return s, sec, self.pw.text()


def main(argv=None) -> int:
    app = QApplication(sys.argv if argv is None else argv)
    app.setApplicationName("Security Center Sentinel")
    app.setDesktopFileName("sentinel-gui")
    app.setWindowIcon(QIcon.fromTheme("security-high"))
    app.setStyleSheet(CSS)
    w = Main()
    w.showMaximized()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
