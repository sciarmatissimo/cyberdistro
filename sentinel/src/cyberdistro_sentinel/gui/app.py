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
                               QListWidgetItem, QMainWindow, QMessageBox, QPushButton, QRadioButton,
                               QScrollArea, QSizePolicy, QSpinBox, QSplitter, QStackedWidget, QTextBrowser,
                               QVBoxLayout, QWidget)

from .. import __version__
from ..assistant import LLM, answer_free, answer_question, describe_device, explain, last_scan_of, network_facts
from ..knowledge import parse_nmap_open, ports_from_result, summarize_ports
from ..config import Paths
from ..devices import TYPE_LABEL, guess_type, vendor
from ..report import write as write_report
from ..store import Store
from ..templates import card
from .. import agent as ag
from .. import inspect as insp
from .. import netcheck as nc

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
QPushButton:disabled, QPushButton#danger:disabled, QPushButton#primary:disabled { background: #f1f3f4; color: #9aa0a6; border: 1px solid #e0e0e0; }
QListWidget { background: #ffffff; border: 1px solid #dadce0; border-radius: 8px; }
QTextBrowser, QLineEdit { background: #ffffff; border: 1px solid #dadce0; border-radius: 8px; padding: 6px; }
"""


# ------------------------------------------------------------------ helpers
class _Sig(QObject):
    done = Signal(object)


# Strong references to in-flight jobs. A QRunnable autodeletes right after run()
# returns; if the cross-thread "done" signal has not yet been delivered to the
# GUI event loop, deleting the Job (and its _Sig sender) silently drops the
# queued slot and the callback never fires — a UI control would stay stuck on
# "…in corso". Holding the Job here until its callback has actually run keeps
# the sender alive so the queued signal is always delivered.
_LIVE_JOBS: set = set()


class Job(QRunnable):
    """Run a function in the thread pool and deliver its result on the GUI thread."""

    def __init__(self, fn, cb):
        super().__init__()
        self.setAutoDelete(False)                 # we manage the lifetime ourselves
        self.fn, self.sig = fn, _Sig()
        self.sig.done.connect(self._deliver)
        self._cb = cb
        _LIVE_JOBS.add(self)

    def _deliver(self, res):                       # runs on the GUI thread
        try:
            self._cb(res)
        finally:
            _LIVE_JOBS.discard(self)

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
    """Yes/no question with Italian buttons (Qt's standard ones are in English here)."""
    box = QMessageBox(QMessageBox.Question, title, text, parent=parent)
    yes = box.addButton("Sì", QMessageBox.YesRole)
    no = box.addButton("No", QMessageBox.NoRole)
    box.setDefaultButton(no)
    box.exec()
    return box.clickedButton() is yes


# ------------------------------------------------------------------ data
class Data:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.status: dict = {"colour": "grigio", "missing": ["sentinel-core"]}
        self.incidents: list[dict] = []
        self.devices: list[dict] = []
        self.actions: list[dict] = []
        self.tasks: list[dict] = []
        self.agent_logs: list[dict] = []
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
                self.tasks = st.tasks()
                self.agent_logs = st.agent_logs()
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
                            ("Protezione", self.page_protection), ("Attività AI", self.page_agent),
                            ("Assistente AI", self.page_assistant),
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
                                                          self.data.incidents, self.data.devices))
                               + self._agent_note())

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

    # ---------------------------------------------------------------- Attività AI (agent)
    def page_agent(self, v):
        v.addWidget(label("Attività AI", "h1"))
        v.addWidget(label("Qui vedi cosa fa l'agente di Sentinel: cosa ha notato, cosa propone di fare per proteggere "
                          "questo PC e cosa è già stato fatto. Con il livello «Chiede» nessuna azione parte senza il tuo "
                          "«Approva». Le azioni di difesa agiscono solo su questo PC. Gli strumenti qui sotto guardano "
                          "l'intera rete (solo la tua): la mappa completa trova tutti i dispositivi, e l'ispezione "
                          "mostra con chi parlano — parte solo quando lo chiedi tu.", "muted"))
        f, l = cardframe()
        row = QHBoxLayout()
        row.addWidget(label("Livello di autonomia:", None, False))
        self.ag_level = QComboBox()
        self.ag_level.addItem("Chiede — prepara le azioni e aspetta il tuo «Approva»", "chiede")
        self.ag_level.addItem("Osserva — solo consigli, nessuna azione", "osserva")
        self.ag_level.addItem("Protezione automatica — esegue da solo le azioni locali e reversibili", "auto")
        self.ag_level.activated.connect(self.agent_set_level)
        row.addWidget(self.ag_level, 1)
        self.ag_stop = QPushButton("Ferma l'agente")
        self.ag_stop.setObjectName("danger")
        self.ag_stop.clicked.connect(self.agent_toggle)
        row.addWidget(self.ag_stop)
        l.addLayout(row)
        self.ag_own = QCheckBox("Questa è la mia rete: l'agente può vedere tutti i dispositivi (censimento) "
                                "e proporre di esaminarli (Nmap)")
        self.ag_own.clicked.connect(self.agent_set_own)
        l.addWidget(self.ag_own)
        self.ag_census = QCheckBox("Mappa completa della rete: cerca ogni pochi minuti tutti i dispositivi collegati, "
                                   "anche quelli che non parlano con questo PC")
        self.ag_census.clicked.connect(self.agent_set_census)
        l.addWidget(self.ag_census)
        self.ag_state = label("", "muted")
        l.addWidget(self.ag_state)
        tools = QHBoxLayout()
        self.b_netcheck = QPushButton("Controlla questa rete (Wi-Fi e DNS)")
        self.b_netcheck.clicked.connect(self.do_netcheck)
        self.b_inspect = QPushButton("Ispeziona il traffico della rete…")
        self.b_inspect.clicked.connect(self.open_inspect)
        self.b_inspect_stop = QPushButton("Ferma ispezione")
        self.b_inspect_stop.setObjectName("danger")
        self.b_inspect_stop.clicked.connect(self.inspect_stop)
        self.b_inspect_stop.setVisible(False)
        tools.addWidget(self.b_netcheck)
        tools.addWidget(self.b_inspect)
        tools.addWidget(self.b_inspect_stop)
        tools.addStretch()
        l.addLayout(tools)
        self.ag_insp = label("", "muted")
        l.addWidget(self.ag_insp)
        v.addWidget(f)
        self._insp_window: tuple[float, float] | None = None
        self._insp_prev = "idle"
        self._seen_pending = 0
        self._seen_grave = 0
        sp = QSplitter(Qt.Horizontal)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(label("Da approvare e azioni attive", "h2"))
        self.ag_list = QListWidget()
        self.ag_list.setWordWrap(True)
        self.ag_list.currentRowChanged.connect(self.agent_select)
        lv.addWidget(self.ag_list, 1)
        sp.addWidget(left)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        self.ag_view = QTextBrowser()
        rv.addWidget(self.ag_view, 1)
        br = QHBoxLayout()
        self.ag_ok = QPushButton("Approva")
        self.ag_ok.setObjectName("primary")
        self.ag_ok.clicked.connect(self.agent_approve)
        self.ag_no = QPushButton("Rifiuta")
        self.ag_no.clicked.connect(self.agent_reject)
        self.ag_undo = QPushButton("Annulla l'azione")
        self.ag_undo.clicked.connect(self.agent_undo)
        self.ag_ai = QPushButton("Spiegamelo (AI)")
        self.ag_ai.clicked.connect(self.agent_explain)
        for b in (self.ag_ok, self.ag_no, self.ag_undo, self.ag_ai):
            br.addWidget(b)
            b.setEnabled(False)                      # nothing selected yet
        rv.addLayout(br)
        sp.addWidget(right)
        sp.setSizes([420, 640])
        sp.setMinimumHeight(330)
        v.addWidget(sp)
        v.addWidget(label("Cronologia dell'agente", "h2"))
        self.ag_log = QTextBrowser()
        self.ag_log.setMinimumHeight(200)
        v.addWidget(self.ag_log)
        self._ag_rows: list[dict] = []
        self._ag_sel: int | None = None

    def update_agent(self):
        st = self.data.store()
        if not st:
            return
        level = st.meta("agent_level", ag.DEFAULT_LEVEL)
        paused = st.meta("agent_paused", False)
        hb = st.meta("agent_heartbeat", 0) or 0
        self.ag_level.setCurrentIndex({"chiede": 0, "osserva": 1, "auto": 2}.get(level, 0))
        self.ag_stop.setText("Riattiva l'agente" if paused else "Ferma l'agente")
        self.ag_stop.setObjectName("primary" if paused else "danger")
        self.ag_stop.style().unpolish(self.ag_stop)
        self.ag_stop.style().polish(self.ag_stop)
        gw = next((d for d in self.data.devices if d.get("is_gateway")), None)
        own = bool(gw and gw.get("mac") and st.meta("own_network") == gw.get("mac"))
        self.ag_own.setEnabled(bool(gw and gw.get("mac")))
        self.ag_own.setChecked(own)
        self.ag_census.setEnabled(own)
        self.ag_census.setChecked(own and self._census_on())
        if not own and self._census_on():
            self._write_census(False)               # census only on a declared own network
        alive = time.time() - hb < 30
        self.ag_state.setText((("Protezione automatica attiva: l'agente esegue da solo blocchi, prova e router "
                                "fissato; esami e ispezioni restano da approvare. " if level == "auto" and not paused
                                else "")
                               + ("L'agente è FERMO: non propone nulla finché non lo riattivi." if paused else
                                  "L'agente è attivo e osserva gli allarmi." if alive else
                                  "L'agente non risponde (servizio sentinel-agent non attivo)."))
                              + f" Ultimo controllo: {when(hb)}.")
        self._update_inspection(st, own)
        if level == "auto" and not paused:
            self._autorun(st)
        self._notify(st)
        rows = [t for t in self.data.tasks if t["status"] in (ag.PROPOSTA, ag.CONSIGLIO, ag.IN_CORSO, ag.ATTIVA)]
        order = {ag.PROPOSTA: 0, ag.IN_CORSO: 1, ag.ATTIVA: 2, ag.CONSIGLIO: 3}
        rank = {"pin_gateway": 0, "block": 1, "examine": 2, "capture": 3}
        rows.sort(key=lambda t: (order[t["status"]], -int(t["ts"] // 60), rank.get(t["action"], 9), -t["ts"]))
        n_pending = sum(1 for t in rows if t["status"] == ag.PROPOSTA)
        item = self.nav.item(self.pages["Attività AI"])
        item.setText("Attività AI" + (f"  ({n_pending})" if n_pending else ""))
        keys = [(t["id"], t["status"]) for t in rows]
        if keys != getattr(self, "_ag_keys", None):     # first paint (None) always rebuilds
            self._ag_keys = keys
            self._ag_rows = rows
            self.ag_list.blockSignals(True)
            self.ag_list.clear()
            tag = {ag.PROPOSTA: "DA APPROVARE", ag.IN_CORSO: "IN CORSO", ag.ATTIVA: "ATTIVA", ag.CONSIGLIO: "CONSIGLIO"}
            col = {ag.PROPOSTA: "#b06000", ag.IN_CORSO: "#1a73e8", ag.ATTIVA: "#188038", ag.CONSIGLIO: "#5f6368"}
            sel_row = -1
            for n, t in enumerate(rows):
                extra = ""
                if t["status"] == ag.ATTIVA and t.get("expires_ts"):
                    extra = f" · scade tra {max(0, int((t['expires_ts'] - time.time()) // 3600))} h"
                it = QListWidgetItem(f"{tag[t['status']]} · {ag.label(t)}\n{when(t['ts'])}{extra}")
                it.setForeground(QColor(col[t["status"]]))
                self.ag_list.addItem(it)
                if t["id"] == self._ag_sel:
                    sel_row = n
            if not rows:
                self.ag_list.addItem(QListWidgetItem("Nessuna proposta in attesa e nessuna azione attiva."))
            self.ag_list.blockSignals(False)
            if sel_row >= 0:
                self.ag_list.setCurrentRow(sel_row)
            self.agent_select(self.ag_list.currentRow())
        e = html.escape
        lines = []
        for g in self.data.agent_logs[:120]:
            lines.append(f"<p><b>{e(datetime.fromtimestamp(g['ts']).strftime('%d/%m %H:%M:%S'))}</b> — {e(g['text'])}</p>")
        txt = "".join(lines) or "<p>Ancora nessuna attività.</p>"
        if txt != getattr(self, "_ag_log_txt", None):
            self._ag_log_txt = txt
            self.ag_log.setHtml(txt)

    def _agent_note(self) -> str:
        n = sum(1 for t in self.data.tasks if t["status"] == ag.PROPOSTA)
        return (f"\nL'agente ha {n} {'proposta' if n == 1 else 'proposte'} di protezione da approvare: "
                "apri «Attività AI».") if n else ""

    def _ag_task(self):
        r = self.ag_list.currentRow()
        return self._ag_rows[r] if 0 <= r < len(self._ag_rows) else None

    def agent_select(self, _row=None):
        t = self._ag_task()
        self._ag_sel = t["id"] if t else None
        for b in (self.ag_ok, self.ag_no, self.ag_undo, self.ag_ai):
            b.setEnabled(False)
        if not t:
            self.ag_view.setHtml("<p>Seleziona una voce per vedere cosa propone l'agente e perché.</p>")
            return
        e = html.escape
        inc = next((i for i in self.data.incidents if i["key"] == t["incident_key"]), None)
        h = f"<h2>{e(ag.label(t))}</h2>"
        h += f"<p><b>Perché:</b> {e(t['reason'] or '')}</p>"
        h += f"<p><b>Cosa succede se approvi:</b> {e(ag.effect(t))}</p>"
        if inc:
            h += f"<p><b>Cosa consiglia la scheda dell'allarme:</b> {e(card(inc)['todo'])}</p>"
        ctx = next((x for x in self.data.tasks if x["action"] == "context" and x["incident_key"] == t["incident_key"]
                    and isinstance(x.get("result"), dict)), None)
        if ctx:
            h += f"<p><b>Contesto raccolto su {e(ctx['target'])}:</b> {e(ag.context_text(ctx['result']))}</p>"
            if self.advanced and ctx["result"].get("dns_names"):
                h += ("<p><b>Nomi cercati (dati arrivati dalla rete):</b> "
                      + e(", ".join(ctx["result"]["dns_names"])) + "</p>")
        if isinstance(t.get("result"), dict) and t["result"].get("output"):
            h += f"<p><b>Esito:</b> {e(t['result']['output'])}</p>"
        if t["status"] == ag.CONSIGLIO:
            h += ("<p><i>Livello «Osserva»: è solo un consiglio. Per poterlo approvare da qui, scegli il livello "
                  "«Chiede».</i></p>")
        self.ag_view.setHtml(h)
        self.ag_ok.setEnabled(t["status"] == ag.PROPOSTA)
        self.ag_no.setEnabled(t["status"] in (ag.PROPOSTA, ag.CONSIGLIO))
        self.ag_undo.setEnabled(t["status"] == ag.ATTIVA)
        self.ag_ai.setEnabled(True)

    def _ag_runner(self, cmd, timeout):
        return run(cmd, timeout)

    def agent_approve(self):
        t = self._ag_task()
        st = self.data.store()
        if not t or not st or t["status"] != ag.PROPOSTA:
            return
        st.agent_log(f"Approvato dall'utente: {ag.lc(ag.label(t))}.", t["id"])
        self.ag_ok.setEnabled(False)
        self.say_status(f"In corso: {ag.lc(ag.label(t))}…")

        def done(res):
            nt = res if isinstance(res, dict) else None
            if nt and nt["status"] in (ag.ATTIVA, ag.COMPLETATA):
                msg = f"Fatto: {ag.lc(ag.label(nt))}."
                r = nt.get("result") or {}
                if nt["action"] == "examine" and isinstance(r, dict):
                    msg += "\n\n" + r.get("summary", "")
                if nt["action"] == "capture" and isinstance(r, dict):
                    msg += "\n\nFile: " + r.get("file", "")
                QMessageBox.information(self, "Attività AI", msg)
            else:
                QMessageBox.warning(self, "Attività AI", "L'azione non è riuscita: vedi la cronologia dell'agente.")
            self.refresh()
        self.pool.start(Job(lambda: ag.execute(Store(self.paths.db), t, self._ag_runner, ["pkexec"]), done))

    def agent_reject(self):
        t = self._ag_task()
        st = self.data.store()
        if t and st:
            ag.reject(st, t)
            self.refresh()

    def agent_undo(self):
        t = self._ag_task()
        st = self.data.store()
        if t and st and t["status"] == ag.ATTIVA:
            ag.undo(st, t, self._ag_runner, ["pkexec"])
            self.refresh()

    def agent_set_level(self, _i=None):
        st = self.data.store()
        if st:
            lv = self.ag_level.currentData()
            st.set_meta("agent_level", lv, commit=True)
            st.agent_log("Livello di autonomia impostato su «" + ("Chiede" if lv == "chiede" else "Osserva") + "».")
            self.refresh()

    def agent_set_own(self, on):
        st = self.data.store()
        gw = next((d for d in self.data.devices if d.get("is_gateway")), None)
        if not st or not gw:
            return
        if on and not confirm(self, "La mia rete", "Confermi che questa rete è tua (o che hai il permesso di "
                              "esaminarla)? Esaminare dispositivi di reti altrui può essere illegale."):
            self.ag_own.setChecked(False)
            return
        st.set_meta("own_network", gw.get("mac") if on else None, commit=True)
        st.agent_log("Rete dichiarata come tua: l'agente può proporre esami dei dispositivi nuovi." if on else
                     "Rete non più dichiarata come tua: niente proposte di esame.")
        self.refresh()

    def agent_toggle(self):
        st = self.data.store()
        if not st:
            return
        if st.meta("agent_paused", False):
            st.set_meta("agent_paused", False, commit=True)
            st.agent_log("Agente riattivato dall'utente.")
            self.refresh()
            return
        if not confirm(self, "Ferma l'agente", "Fermare l'agente? Le proposte in attesa vengono rifiutate e le "
                       "azioni attive (blocchi, router fissato) vengono annullate."):
            return
        st.set_meta("agent_paused", True, commit=True)
        for t in self.data.tasks:
            if t["status"] in (ag.PROPOSTA, ag.CONSIGLIO):
                ag.reject(st, t, "agente fermato")
            elif t["status"] == ag.ATTIVA:
                ag.undo(st, t, self._ag_runner, ["pkexec"])
        st.agent_log("Agente fermato dall'utente: proposte rifiutate, azioni annullate.")
        self.refresh()

    # ---------------- census (2a) ----------------
    def _census_path(self) -> Path:
        return self.paths.state_dir / "census.json"

    def _census_on(self) -> bool:
        try:
            return bool(json.loads(self._census_path().read_text()).get("enabled"))
        except (OSError, ValueError):
            return False

    def _write_census(self, on: bool):
        try:
            p = self._census_path()
            p.write_text(json.dumps({"enabled": bool(on)}))
            try:
                p.chmod(0o664)
            except OSError:
                pass
        except OSError as e:               # noqa: BLE001
            self.say_status(f"Non riesco a salvare l'impostazione del censimento: {e}")

    def agent_set_census(self, on):
        st = self.data.store()
        gw = next((d for d in self.data.devices if d.get("is_gateway")), None)
        if not st or not gw or st.meta("own_network") != gw.get("mac"):
            self.ag_census.setChecked(False)
            return
        self._write_census(on)
        if st:
            st.agent_log("Mappa completa della rete attivata: cerco tutti i dispositivi collegati." if on else
                         "Mappa completa della rete disattivata.")
        self.refresh()

    # ---------------- automatic protection (2c) ----------------
    def _autorun(self, st):
        inflight = getattr(self, "_autorun_ids", set())
        for t in self.data.tasks:
            if (t["status"] == ag.PROPOSTA and t["action"] in ag.AUTO_ACTIONS and t["id"] not in inflight):
                inflight.add(t["id"])
                self._autorun_ids = inflight
                st.agent_log(f"Protezione automatica: eseguo {ag.lc(ag.label(t))}.", t["id"])

                def done(res, tid=t["id"]):
                    self._autorun_ids.discard(tid)
                    self.refresh()
                self.pool.start(Job(lambda t=t: ag.execute(Store(self.paths.db), t, self._ag_runner, ["pkexec"]), done))

    # ---------------- desktop notifications (2c) ----------------
    def _notify(self, st):
        pending = sum(1 for t in self.data.tasks if t["status"] == ag.PROPOSTA)
        grave = [i for i in self.data.incidents if i["severity"] == "alta" and i.get("status", "aperto") == "aperto"]
        grave_n = len(grave)
        if not getattr(self, "_notify_ready", False):   # first paint: learn the baseline, don't toast
            self._seen_pending, self._seen_grave, self._notify_ready = pending, grave_n, True
            return
        if st.meta("agent_level", ag.DEFAULT_LEVEL) == "osserva":
            self._seen_pending, self._seen_grave = pending, grave_n
            return
        if pending > self._seen_pending and pending:
            self._toast("Sentinel: azione da approvare",
                        f"{pending} proposta/e di protezione ti aspettano in «Attività AI».")
        if grave_n > self._seen_grave and grave_n:
            self._toast("Sentinel: allarme grave", card(grave[0])["title"])
        self._seen_pending, self._seen_grave = pending, grave_n

    def _toast(self, title, body):
        if self.smoke:
            return
        try:
            subprocess.Popen(["notify-send", "-a", "Sentinel", "-i", "security-high", title, body])
        except OSError:
            pass

    # ---------------- deep inspection (2b) ----------------
    def _update_inspection(self, st, own):
        state = insp.read_state(self.paths.run_dir)
        running = state.get("state") == "running"
        self.b_inspect.setVisible(not running)
        self.b_inspect_stop.setVisible(running)
        self.b_inspect.setEnabled(own)
        self.b_inspect.setToolTip("" if own else "Prima dichiara che questa è la tua rete.")
        if running:
            self._insp_window = (state.get("started", time.time()), state.get("ends", time.time()))
            left = max(0, int(state.get("ends", 0) - time.time()))
            scope = "tutta la rete" if state.get("target") == "all" else state.get("target")
            self.ag_insp.setText(f"Ispezione del traffico in corso ({scope}) — mancano {left // 60}:{left % 60:02d}. "
                                 "Suricata e Zeek stanno analizzando il traffico di tutti i dispositivi.")
        else:
            self.ag_insp.setText("")
        if self._insp_prev == "running" and not running and self._insp_window:
            self._show_inspection_results(*self._insp_window)
            self._insp_window = None
        self._insp_prev = state.get("state", "idle")

    def _self_and_gw(self):
        self_ips = {d["ip"] for d in self.data.devices if d.get("is_self") and d.get("ip")}
        self_ips |= ag.local_ips()
        gw = next((d.get("ip") for d in self.data.devices if d.get("is_gateway")), None)
        return self_ips, gw

    def _show_inspection_results(self, t0, t1):
        self_ips, gw = self._self_and_gw()
        try:
            devs = insp.summarize(self.paths.zeek_dir, t0, t1, self_ips, gw)
        except Exception as e:                      # noqa: BLE001
            devs = []
            print("inspect summary:", e, file=sys.stderr)
        st = self.data.store()
        if st:
            st.agent_log(f"Ispezione del traffico terminata: {len(devs)} dispositivi osservati, rete ripristinata.")
        e = html.escape
        if not devs:
            body = ("<p>L'ispezione è terminata. Non ho un riepilogo per dispositivo: potrebbe essere servito più "
                    "tempo, oppure sulla rete passava poco traffico durante l'ispezione.</p>")
        else:
            body = "<p>Ecco cosa ha fatto ogni dispositivo durante l'ispezione (solo metadati; il contenuto cifrato " \
                   "non è visibile):</p>"
            for d in devs[:25]:
                body += f"<p><b>{e(insp.device_line(d))}</b>"
                if d["dns_names"]:
                    body += "<br>Siti/nomi cercati: " + e(", ".join(d["dns_names"][:8]))
                body += "</p>"
        dlg = QDialog(self)
        dlg.setWindowTitle("Ispezione del traffico — risultati")
        dlg.setMinimumSize(640, 480)
        lay = QVBoxLayout(dlg)
        tb = QTextBrowser()
        tb.setHtml(body)
        lay.addWidget(tb)
        bb = QDialogButtonBox()
        bb.addButton("Chiudi", QDialogButtonBox.AcceptRole)
        bb.accepted.connect(dlg.accept)
        lay.addWidget(bb)
        dlg.exec()

    def open_inspect(self):
        st = self.data.store()
        gw = next((d for d in self.data.devices if d.get("is_gateway")), None)
        if not st or not gw or st.meta("own_network") != gw.get("mac"):
            QMessageBox.information(self, "Ispezione del traffico",
                                    "Prima spunta «Questa è la mia rete». L'ispezione è consentita solo sulla tua rete.")
            return
        others = [d for d in self.data.devices if d.get("ip") and not d.get("is_self") and not d.get("is_gateway")]
        dlg = InspectDialog(others, self)
        if dlg.exec() != QDialog.Accepted:
            return
        minutes, target = dlg.choice()
        self.say_status("Avvio dell'ispezione del traffico…")

        def done(res):
            code, out = res if not isinstance(res, Exception) else (1, str(res))
            if code != 0:
                QMessageBox.warning(self, "Ispezione del traffico", "Non sono riuscito ad avviare l'ispezione.\n\n" + out[-500:])
            self.refresh()
        self.pool.start(Job(lambda: run(["pkexec", "/usr/local/sbin/sentinel-inspect", "start",
                                         str(minutes), target], 60), done))

    def inspect_stop(self):
        self.say_status("Fermo l'ispezione…")

        def done(_res):
            self.refresh()
        self.pool.start(Job(lambda: run(["pkexec", "/usr/local/sbin/sentinel-inspect", "stop"], 30), done))

    # ---------------- Wi-Fi / DNS check (2c) ----------------
    def do_netcheck(self):
        self.b_netcheck.setEnabled(False)
        self.b_netcheck.setText("Controllo in corso…")

        def work():
            code, wifi = run(["nmcli", "-t", "-f", "IN-USE,SSID,SECURITY,CHAN,SIGNAL,BSSID", "device", "wifi"], 20)
            findings = nc.wifi_findings(wifi if code == 0 else "")
            import socket as _s
            rand = f"cyberdistro-{int(time.time())}-xq.example-no-such-domain-{os.getpid()}.com"
            answers = []
            try:
                answers = [ai[4][0] for ai in _s.getaddrinfo(rand, None)]
            except Exception:                        # noqa: BLE001 — NXDOMAIN is the good case
                pass
            findings += nc.dns_findings(rand, answers)
            return findings

        def done(res):
            self.b_netcheck.setEnabled(True)
            self.b_netcheck.setText("Controlla questa rete (Wi-Fi e DNS)")
            findings = res if isinstance(res, list) else []
            self._show_netcheck(findings)
            st = self.data.store()
            if st:
                worst = nc.worst(findings)
                st.agent_log("Controllo della rete: " + {"ok": "nessun problema.", "info": "nessun problema rilevante.",
                             "warn": "attenzione, qualcosa da sistemare.", "danger": "attenzione, rete non sicura."}.get(worst, ""))
        self.pool.start(Job(work, done))

    def _show_netcheck(self, findings):
        e = html.escape
        # the kiosk font has no emoji; use words instead of coloured dots
        word = {"ok": "OK", "info": "Info", "warn": "Attenzione", "danger": "Pericolo"}
        body = "".join(f"<p><b>[{word.get(f['level'], '')}] {e(f['title'])}</b><br>{e(f['detail'])}</p>"
                       for f in findings) if findings else "<p>Nessun controllo disponibile (sei connesso via cavo?).</p>"
        dlg = QDialog(self)
        dlg.setWindowTitle("Controllo della rete")
        dlg.setMinimumSize(560, 400)
        lay = QVBoxLayout(dlg)
        tb = QTextBrowser()
        tb.setHtml(body)
        lay.addWidget(tb)
        bb = QDialogButtonBox()
        bb.addButton("Chiudi", QDialogButtonBox.AcceptRole)
        bb.accepted.connect(dlg.accept)
        lay.addWidget(bb)
        dlg.exec()

    def agent_explain(self):
        t = self._ag_task()
        if not t:
            return
        inc = next((i for i in self.data.incidents if i["key"] == t["incident_key"]), None)
        facts = ag.task_facts(t, inc)
        ok, why = self.llm.availability()
        if not ok:
            QMessageBox.information(self, "Spiegazione", "Il modello AI non è disponibile (" + why + ").\n\n"
                                    + ag.effect(t))
            return
        self.ag_ai.setEnabled(False)
        self.say_status("Il modello AI sta preparando la spiegazione (20–60 secondi)…")

        def done(res):
            self.ag_ai.setEnabled(True)
            if isinstance(res, Exception) or not res or not res[0] or res[1]:
                QMessageBox.information(self, "Spiegazione", "Non ho una spiegazione verificata del modello. "
                                        + (t["reason"] or "") + "\n\n" + ag.effect(t))
                return
            QMessageBox.information(self, "Spiegazione (AI locale, verificata)", res[0])
        q = "Spiega in parole semplici a una persona non esperta perché questa azione è utile e cosa cambia."
        self.pool.start(Job(lambda: answer_free(q, facts, self.llm), done))

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
            try:
                st.close_incident(self.selected_inc["key"])
            except Exception as e:              # noqa: BLE001
                QMessageBox.warning(self, "Segna come gestito", f"Non riesco a salvare: {e}")
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
        self._log("blocco 24 ore", ip, out[:200] if code == 0 else "errore: " + out[:200])
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
        aid = self._log("scansione rete", str(netw), "in corso")

        def done(res):
            code, out = res if not isinstance(res, Exception) else (1, str(res))
            n = out.count("Host is up")
            self._finish(aid, f"dispositivi che hanno risposto: {n}")
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

        aid = self._log("scansione dispositivo", d["ip"], "in corso")
        self.say_status(f"Esame di {d['ip']} in corso…")

        def done(res):
            code, out = res if not isinstance(res, Exception) else (1, str(res))
            ports = parse_nmap_open(out)
            ok = code == 0 and "Nmap done" in out
            result = (("porte aperte: " + ", ".join(map(str, ports))) if ports else "nessuna porta comune aperta") \
                if ok else "esame non riuscito"
            self._finish(aid, result)
            if not ok:
                msg = "L'esame non è riuscito.\n" + out[-400:]
            else:
                msg = summarize_ports(ports)
                msg += ("\n\nSentinel ha controllato le 100 porte più comuni. Questa scansione è registrata come "
                        "attività tua: non comparirà come attacco.")
            if self.advanced:
                msg += "\n\nComando: nmap -Pn -sT -F -T3 " + d["ip"]
            QMessageBox.information(self, f"Risultato per {d['ip']}", msg)
            self.refresh()
            if self.sel_dev and self.sel_dev.get("ip") == d["ip"]:
                self.show_device(self.sel_dev)
        # -Pn: the device is already on the map; many devices ignore ping and would look "down"
        self.pool.start(Job(lambda: run(["nmap", "-Pn", "-sT", "-F", "-T3", d["ip"]], 600), done))

    def _log(self, action, target, result):
        """Record a user action; scans recorded here are shown as the user's own activity."""
        st = self.data.store()
        try:
            return st.log_action(action, target, result) if st else None
        except Exception as e:                  # noqa: BLE001 — never block the action itself
            self.say_status(f"Attenzione: non riesco a registrare l'azione ({e}).")
            return None

    def _finish(self, aid, result):
        st = self.data.store()
        if st and aid:
            try:
                st.finish_action(aid, result)
            except Exception:                   # noqa: BLE001
                pass

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
        for fn in (self.update_home, self.update_network, self.update_protection, self.update_agent,
                   self.update_report, self.update_settings):
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


class InspectDialog(QDialog):
    """Consent-gated setup for the deep traffic inspection (2b): how long, which
    devices, with a plain warning and a mandatory consent tick."""

    def __init__(self, others, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ispeziona il traffico della rete")
        self.setMinimumSize(560, 520)
        self.others = [d for d in others if d.get("ip")]
        v = QVBoxLayout(self)
        v.addWidget(label("Ispezione del traffico della rete", "h2"))
        warn = QTextBrowser()
        warn.setHtml(
            "<p>Per il tempo che scegli, Sentinel fa passare da questo PC il traffico degli altri dispositivi "
            "(continuando a inoltrarlo, quindi la rete <b>non si interrompe</b>) per mostrarti con chi parlano. "
            "Al termine si ferma da sola e rimette a posto la rete.</p>"
            "<p>Vedrai solo <b>chi parla con chi</b>, quanto e quali siti vengono cercati: il contenuto del "
            "traffico cifrato (HTTPS) resta illeggibile.</p>"
            "<p><b>Usa questa funzione solo sulla tua rete e solo con il consenso di chi la usa.</b> "
            "Intercettare le comunicazioni altrui senza permesso può essere illegale "
            "(in Italia, artt. 617 e seguenti del codice penale).</p>")
        warn.setMaximumHeight(210)
        v.addWidget(warn)
        row = QHBoxLayout()
        row.addWidget(label("Durata (minuti):", None, False))
        self.spin = QSpinBox()
        self.spin.setRange(1, insp.MAX_MINUTES)
        self.spin.setValue(insp.DEFAULT_MINUTES)
        row.addWidget(self.spin)
        row.addStretch()
        v.addLayout(row)
        self.r_all = QRadioButton("Tutta la rete (tutti i dispositivi)")
        self.r_all.setChecked(True)
        v.addWidget(self.r_all)
        row2 = QHBoxLayout()
        self.r_one = QRadioButton("Solo un dispositivo:")
        row2.addWidget(self.r_one)
        self.combo = QComboBox()
        for d in self.others:
            self.combo.addItem(f"{d['ip']} — {TYPE_LABEL['it'][guess_type(d)]}", d["ip"])
        self.combo.setEnabled(False)
        self.r_one.toggled.connect(self.combo.setEnabled)
        row2.addWidget(self.combo, 1)
        v.addLayout(row2)
        self.consent = QCheckBox("Confermo che questa è la mia rete e che ho il consenso di chi la usa.")
        v.addWidget(self.consent)
        bb = QDialogButtonBox()
        self.ok = bb.addButton("Avvia ispezione", QDialogButtonBox.AcceptRole)
        self.ok.setEnabled(False)
        bb.addButton("Annulla", QDialogButtonBox.RejectRole)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        self.consent.toggled.connect(self.ok.setEnabled)
        if not self.others:
            self.r_one.setEnabled(False)
        v.addWidget(bb)

    def choice(self):
        if self.r_one.isChecked() and self.combo.count():
            return self.spin.value(), self.combo.currentData()
        return self.spin.value(), "all"


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
