"""CyberDistro — Security Center GUI (PySide6), bilingual (it/en).

Presentation layer only: every action calls into ``cyberdistro_sc.core`` or
``cyberdistro_sc.tools``. The GUI never computes results itself and, in the
Professional/Expert modes, always shows the underlying command before running
it (honesty + reproducibility).

Language: the default comes from CYBERDISTRO_LANG (set per-edition at build
time). User-facing strings go through either the i18n table (_t) or the inline
bilingual helper L(it, en); data catalogs expose localized accessors.

Pages (left sidebar):
  * Explore        — who is on the network / Bluetooth, one tile per device.
  * Overview       — Beginner: big action tiles; Pro/Expert: system report.
  * Forensics / Reversing — on-demand application sections.
  * Network monitor — guided transparent-bridge tap (2 NICs).
  * Tools          — catalog by operational goal (Pro/Expert).
  * Privacy        — Tor/kill-switch posture, profile switch, Tor Browser.
  * Projects / Reports — Pro/Expert (CLI-backed).
  * Learn          — plain-language explanations.

The mode switch (Beginner / Professional / Expert) is reversible and only
changes what is shown — never what is recorded.
"""

from __future__ import annotations

import html
import os
import shutil
import subprocess
import sys

from ..core.catalog import Catalog
from ..core.capabilities import system_report
from ..core.modes import Mode
from ..i18n import t as _t, default_lang
from ..tools import explore as ex
from ..tools import privacy_status as ps
from ..tools import appstore as appstore
from ..tools import netmonitor as netmon
from ..tools import keyboard as kbd
from ..tools import assistant as ai
from .. import __version__


def L(it: str, en: str) -> str:
    """Inline bilingual string: returns the English text in the EN edition."""
    return en if default_lang() == "en" else it


def mode_label(m: "Mode") -> str:
    return {Mode.BEGINNER: L("Principiante", "Beginner"),
            Mode.PROFESSIONAL: L("Professionista", "Professional"),
            Mode.EXPERT: L("Esperto", "Expert")}[m]


# Fallback glyphs when the icon theme has no icon (e.g. headless tests).
KIND_GLYPH = {
    "self": "💻", "router": "📡", "computer": "🖥", "phone": "📱", "printer": "🖨",
    "tv": "📺", "camera": "📷", "audio": "🎧", "input": "⌨", "wearable": "⌚",
    "iot": "🔌", "unknown": "❔",
}
KIND_COLOR = {
    "self": "#0a84ff", "router": "#30d158", "computer": "#5e5ce6", "phone": "#ff9f0a",
    "printer": "#8e8e93", "tv": "#bf5af2", "camera": "#ff375f", "audio": "#64d2ff",
    "input": "#ac8e68", "wearable": "#ff6482", "iot": "#ffd60a", "unknown": "#98989d",
}

KIND_EXPLAIN = {
    "self": (L, "È il computer che stai usando adesso.", "This is the computer you are using now."),
    "router": (L, "È il dispositivo che collega la tua rete a Internet (modem/router). "
                  "Di solito è fornito dall'operatore o acquistato da te.",
               "The device that connects your network to the Internet (modem/router). "
               "Usually provided by your ISP or bought by you."),
    "computer": (L, "Un computer fisso o portatile collegato alla tua rete.",
                 "A desktop or laptop connected to your network."),
    "phone": (L, "Uno smartphone o un tablet collegato alla rete.",
              "A smartphone or tablet connected to the network."),
    "printer": (L, "Una stampante o uno scanner di rete.", "A network printer or scanner."),
    "tv": (L, "Una smart TV o un lettore multimediale.", "A smart TV or media player."),
    "camera": (L, "Una videocamera o telecamera connessa.", "A connected camera."),
    "audio": (L, "Cuffie, auricolari o altoparlanti.", "Headphones, earbuds or speakers."),
    "input": (L, "Tastiera, mouse o controller.", "Keyboard, mouse or controller."),
    "wearable": (L, "Smartwatch o braccialetto fitness.", "Smartwatch or fitness band."),
    "iot": (L, "Un dispositivo «smart» (presa, lampadina, sensore, assistente vocale…).",
            "A 'smart' device (plug, bulb, sensor, voice assistant…)."),
    "unknown": (L, "Non è stato possibile riconoscere il tipo: è comunque un dispositivo "
                   "presente. Se non lo riconosci, verifica chi lo possiede.",
                "The type could not be recognized: it is still a device that is present. "
                "If you don't recognize it, check who owns it."),
}


def kind_explain(kind: str) -> str:
    row = KIND_EXPLAIN.get(kind)
    return L(row[1], row[2]) if row else ""


def _require_qt():
    try:
        from PySide6 import QtWidgets, QtCore, QtGui  # noqa: F401
        return QtWidgets, QtCore, QtGui
    except Exception as e:  # pragma: no cover - environment dependent
        raise SystemExit(
            "PySide6 non è installato / is not installed. "
            "Install 'python3-pyside6.*' or `pip install PySide6`.\n"
            f"Detail: {e}"
        )


def build_app(argv=None):  # pragma: no cover - requires Qt
    """Create (QApplication, MainWindow) without entering the event loop."""
    QtWidgets, QtCore, QtGui = _require_qt()

    # ------------------------------------------------------------ helpers
    def kind_icon(kind: str, size: int = 64) -> "QtGui.QIcon":
        for name in ex.icon_candidates(kind):
            if QtGui.QIcon.hasThemeIcon(name):
                return QtGui.QIcon.fromTheme(name)
        pm = QtGui.QPixmap(size, size)
        pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setBrush(QtGui.QColor(KIND_COLOR.get(kind, "#98989d")))
        p.setPen(QtCore.Qt.NoPen)
        p.drawEllipse(2, 2, size - 4, size - 4)
        f = p.font()
        f.setPixelSize(int(size * 0.5))
        p.setFont(f)
        p.setPen(QtGui.QColor("white"))
        p.drawText(pm.rect(), QtCore.Qt.AlignCenter, KIND_GLYPH.get(kind, "❔"))
        p.end()
        return QtGui.QIcon(pm)

    def h1(text):
        return QtWidgets.QLabel(f"<h1 style='margin:0'>{html.escape(text)}</h1>")

    def muted(text):
        lbl = QtWidgets.QLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet("color: palette(mid);")
        return lbl

    def card(title: str | None = None):
        box = QtWidgets.QFrame()
        box.setObjectName("Card")
        box.setStyleSheet(
            "#Card { background: palette(base); border: 1px solid palette(midlight);"
            " border-radius: 14px; }")
        lay = QtWidgets.QVBoxLayout(box)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
        if title:
            lay.addWidget(QtWidgets.QLabel(f"<b style='font-size:15px'>{html.escape(title)}</b>"))
        return box, lay

    def chip(text, good):
        lbl = QtWidgets.QLabel(("● " if good else "○ ") + text)
        lbl.setStyleSheet("padding: 6px 12px; border-radius: 12px; border: 1px solid palette(midlight);"
                          f" color: {'#30d158' if good else 'palette(mid)'};")
        return lbl

    # ----------------------------------------------------- AI assistant box
    class AssistantBox(QtWidgets.QWidget):
        """Reusable 'ask the AI' widget. context_getter() returns extra context
        (e.g. the current network-monitor summary) passed to the assistant."""

        def __init__(self, win, context_getter=lambda: "", compact=False):
            super().__init__()
            self.win = win
            self.context_getter = context_getter
            self._worker = None
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            if not compact:
                lay.addWidget(muted(L(
                    "Chiedi all'assistente: funziona tutto in locale (nessun dato esce dal "
                    "PC). Con un modello AI locale avviato risponde a domande libere; "
                    "altrimenti dà spiegazioni di base.",
                    "Ask the assistant: everything runs locally (no data leaves the PC). "
                    "With a local AI model running it answers free-form questions; "
                    "otherwise it gives basic explanations.")))
            row = QtWidgets.QHBoxLayout()
            self.inp = QtWidgets.QLineEdit()
            self.inp.setPlaceholderText(L("Scrivi una domanda… es. «cosa vedo con il bridge?»",
                                          "Type a question… e.g. “what do I see with the bridge?”"))
            self.inp.returnPressed.connect(self.ask)
            self.btn = QtWidgets.QPushButton(L("Chiedi", "Ask"))
            self.btn.setMinimumWidth(110)
            self.btn.clicked.connect(self.ask)
            row.addWidget(self.inp, 1)
            row.addWidget(self.btn)
            lay.addLayout(row)
            self.out = QtWidgets.QTextBrowser()
            self.out.setMinimumHeight(90 if compact else 200)
            lay.addWidget(self.out, 1)

        def ask(self):
            q = self.inp.text().strip()
            if not q or self._worker is not None:
                return
            self.btn.setEnabled(False)
            self.out.setPlainText(L("Sto pensando…", "Thinking…"))
            ctx = ""
            try:
                ctx = self.context_getter() or ""
            except Exception:
                ctx = ""
            self._worker = Worker(ai.answer, q, ctx)
            self._worker.done.connect(self._done)
            self._worker.failed.connect(self._fail)
            self._worker.finished.connect(self._cleanup)
            self._worker.start()

        def _done(self, result):
            text, used_model = result
            tag = (L("🤖 Modello AI locale", "🤖 Local AI model") if used_model
                   else L("💡 Assistente (modalità base)", "💡 Assistant (basic mode)"))
            safe = html.escape(text).replace("\n", "<br>")
            self.out.setHtml(f"<p style='color:gray'>{tag}</p><p>{safe}</p>")
            self.win.log_operation("assistant.ask", 0)
            self.btn.setEnabled(True)

        def _fail(self, msg):
            self.out.setPlainText(msg)
            self.btn.setEnabled(True)

        def _cleanup(self):
            self._worker = None

    # ------------------------------------------------------- worker thread
    class Worker(QtCore.QThread):
        done = QtCore.Signal(object)
        failed = QtCore.Signal(str)

        def __init__(self, fn, *args, **kwargs):
            super().__init__()
            self._fn, self._args, self._kwargs = fn, args, kwargs

        def run(self):
            try:
                self.done.emit(self._fn(*self._args, **self._kwargs))
            except Exception as e:
                self.failed.emit(f"{type(e).__name__}: {e}")

    # ------------------------------------------------------ device dialog
    class DeviceDialog(QtWidgets.QDialog):
        def __init__(self, dev: ex.Device, mode: Mode, command: str, parent=None):
            super().__init__(parent)
            self.setWindowTitle(_t("explore.details"))
            self.setMinimumWidth(460)
            lay = QtWidgets.QVBoxLayout(self)

            head = QtWidgets.QHBoxLayout()
            ic = QtWidgets.QLabel()
            ic.setPixmap(kind_icon(dev.kind, 72).pixmap(72, 72))
            head.addWidget(ic)
            tcol = QtWidgets.QVBoxLayout()
            tcol.addWidget(QtWidgets.QLabel(
                f"<h2 style='margin:0'>{html.escape(dev.display_name)}</h2>"))
            tcol.addWidget(muted(ex.label_for(dev.kind, default_lang())))
            head.addLayout(tcol, 1)
            lay.addLayout(head)

            lay.addWidget(muted(kind_explain(dev.kind)))

            na = L("non disponibile", "not available")
            rows = []
            if dev.source == "network":
                rows.append((L("Indirizzo IP", "IP address"), dev.address))
                rows.append((L("Nome", "Name"), dev.name or na))
            else:
                rows.append((L("Indirizzo Bluetooth", "Bluetooth address"), dev.address))
                rows.append((L("Nome", "Name"), dev.name or L("non annunciato", "not advertised")))
            rows.append((L("Indirizzo fisico (MAC)", "Hardware address (MAC)"), dev.mac or na))
            rows.append((L("Produttore", "Vendor"), dev.vendor or (
                L("non identificabile (indirizzo casuale)", "not identifiable (random address)")
                if dev.details.get("mac_random") == "sì" else na)))
            for k, v in dev.details.items():
                if k == "mac_random":
                    continue
                rows.append((k.capitalize(), str(v)))

            table = QtWidgets.QTableWidget(len(rows), 2)
            table.setHorizontalHeaderLabels([L("Informazione", "Field"), L("Valore", "Value")])
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setStretchLastSection(True)
            table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
            for i, (k, v) in enumerate(rows):
                table.setItem(i, 0, QtWidgets.QTableWidgetItem(k))
                table.setItem(i, 1, QtWidgets.QTableWidgetItem(v))
            table.resizeColumnToContents(0)
            table.setFixedHeight(min(320, 32 + 30 * len(rows)))
            lay.addWidget(table)

            if mode is not Mode.BEGINNER and command:
                lay.addWidget(muted(L("Comando eseguito: ", "Command run: ")
                                    + f"<code>{html.escape(command)}</code>"))
            btns = QtWidgets.QDialogButtonBox()
            btns.addButton(L("Chiudi", "Close"), QtWidgets.QDialogButtonBox.RejectRole)
            btns.rejected.connect(self.reject)
            btns.accepted.connect(self.accept)
            lay.addWidget(btns)

    # ------------------------------------------------------- explore page
    class ExplorePage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            self.win = win
            self.networks = []
            self.net_devices = []
            self.bt_devices = []
            self.last_net_cmd = ""
            self.last_bt_cmd = ""
            self._confirmed = set()
            self._worker = None

            root = QtWidgets.QVBoxLayout(self)
            root.setContentsMargins(28, 24, 28, 24)
            root.addWidget(h1(_t("explore.title")))
            root.addWidget(muted(_t("explore.subtitle")))
            self.tabs = QtWidgets.QTabWidget()
            root.addWidget(self.tabs, 1)

            nt = QtWidgets.QWidget()
            nl = QtWidgets.QVBoxLayout(nt)
            bar = QtWidgets.QHBoxLayout()
            self.net_combo = QtWidgets.QComboBox()
            self.net_combo.setMinimumWidth(260)
            bar.addWidget(QtWidgets.QLabel(L("Rete:", "Network:")))
            bar.addWidget(self.net_combo)
            self.btn_refresh = QtWidgets.QPushButton(L("Aggiorna reti", "Refresh networks"))
            self.btn_refresh.clicked.connect(self.refresh_networks)
            bar.addWidget(self.btn_refresh)
            bar.addStretch(1)
            self.btn_net_scan = QtWidgets.QPushButton(_t("explore.scan"))
            self.btn_net_scan.setDefault(True)
            self.btn_net_scan.setMinimumHeight(36)
            self.btn_net_scan.clicked.connect(self.scan_network)
            bar.addWidget(self.btn_net_scan)
            nl.addLayout(bar)
            self.net_status = muted("")
            nl.addWidget(self.net_status)
            self.net_grid = self._make_grid(lambda: self.last_net_cmd)
            nl.addWidget(self.net_grid, 1)
            self.tabs.addTab(nt, _t("explore.network_tab"))

            bt = QtWidgets.QWidget()
            bl = QtWidgets.QVBoxLayout(bt)
            bbar = QtWidgets.QHBoxLayout()
            bbar.addWidget(QtWidgets.QLabel(L("Durata ascolto:", "Listen duration:")))
            self.bt_seconds = QtWidgets.QSpinBox()
            self.bt_seconds.setRange(3, 60)
            self.bt_seconds.setValue(8)
            self.bt_seconds.setSuffix(" s")
            bbar.addWidget(self.bt_seconds)
            bbar.addStretch(1)
            self.btn_bt_scan = QtWidgets.QPushButton(_t("explore.scan"))
            self.btn_bt_scan.setMinimumHeight(36)
            self.btn_bt_scan.clicked.connect(self.scan_bluetooth)
            bbar.addWidget(self.btn_bt_scan)
            bl.addLayout(bbar)
            self.bt_status = muted("")
            bl.addWidget(self.bt_status)
            self.bt_grid = self._make_grid(lambda: self.last_bt_cmd)
            bl.addWidget(self.bt_grid, 1)
            self.tabs.addTab(bt, _t("explore.bluetooth_tab"))

            self.refresh_networks()
            ok, why = ex.bluetooth_available()
            self.bt_status.setText(L("Pronto: premi «Cerca dispositivi».", "Ready: press “Find devices”.")
                                   if ok else L(f"Bluetooth non disponibile: {why}",
                                                f"Bluetooth unavailable: {why}"))
            self.btn_bt_scan.setEnabled(ok)

        def _make_grid(self, cmd_getter):
            grid = QtWidgets.QListWidget()
            grid.setViewMode(QtWidgets.QListView.IconMode)
            grid.setIconSize(QtCore.QSize(72, 72))
            grid.setGridSize(QtCore.QSize(184, 140))
            grid.setResizeMode(QtWidgets.QListView.Adjust)
            grid.setMovement(QtWidgets.QListView.Static)
            grid.setSpacing(10)
            grid.setWordWrap(True)
            grid.setStyleSheet("QListWidget { font-size: 13px; }"
                               "QListWidget::item { padding: 6px; border-radius: 10px; }")

            def open_details(item):
                dev = item.data(QtCore.Qt.UserRole)
                DeviceDialog(dev, self.win.mode, cmd_getter(), self).exec()
            grid.itemClicked.connect(open_details)
            grid.itemActivated.connect(open_details)
            return grid

        def _fill(self, grid, devices):
            grid.clear()
            for d in devices:
                sub = ex.label_for(d.kind, default_lang())
                item = QtWidgets.QListWidgetItem(kind_icon(d.kind), f"{d.display_name}\n{sub}")
                item.setData(QtCore.Qt.UserRole, d)
                item.setToolTip(f"{d.address}" + (f" · {d.vendor}" if d.vendor else ""))
                item.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
                item.setSizeHint(QtCore.QSize(172, 126))
                grid.addItem(item)

        def refresh_networks(self):
            self.networks = ex.local_networks()
            self.net_combo.clear()
            for n in self.networks:
                extra = L(" (ridotta a /24)", " (reduced to /24)") if n.capped else ""
                self.net_combo.addItem(f"{n.title} — {n.cidr}{extra}", n)
            if not self.networks:
                self.net_status.setText(_t("explore.no_network"))
                self.btn_net_scan.setEnabled(False)
            else:
                self.net_status.setText(L("Pronto: premi «Cerca dispositivi».",
                                          "Ready: press “Find devices”."))
                self.btn_net_scan.setEnabled(True)

        def _confirm_network(self, net) -> bool:
            if net.cidr in self._confirmed:
                return True
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle(_t("explore.confirm_title"))
            lay = QtWidgets.QVBoxLayout(dlg)
            txt = QtWidgets.QLabel(_t("explore.confirm_text").replace(
                "{network}", f"<b>{html.escape(net.title)}</b> ({net.cidr})"))
            txt.setWordWrap(True)
            lay.addWidget(txt)
            if self.win.mode is not Mode.BEGINNER:
                lay.addWidget(muted(L("Comando: ", "Command: ")
                                    + f"<code>{html.escape(ex.plan_network_scan(net.cidr).shell_preview)}</code>"))
            chk = QtWidgets.QCheckBox(_t("explore.confirm_check"))
            lay.addWidget(chk)
            btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
            btns.button(QtWidgets.QDialogButtonBox.Ok).setEnabled(False)
            chk.toggled.connect(btns.button(QtWidgets.QDialogButtonBox.Ok).setEnabled)
            btns.accepted.connect(dlg.accept)
            btns.rejected.connect(dlg.reject)
            lay.addWidget(btns)
            if dlg.exec() == QtWidgets.QDialog.Accepted and chk.isChecked():
                self._confirmed.add(net.cidr)
                return True
            return False

        def scan_network(self):
            net = self.net_combo.currentData()
            if net is None or self._worker is not None:
                return
            if not self._confirm_network(net):
                self.net_status.setText(L("Ricerca annullata: nessuna conferma.",
                                          "Search cancelled: no confirmation."))
                return
            auth = ex.local_authorization(net, owner=os.environ.get("USER", "utente"),
                                          confirmed=True)
            self.net_status.setText(_t("explore.scanning"))
            self.btn_net_scan.setEnabled(False)
            self._worker = Worker(ex.scan_network, net, auth)
            self._worker.done.connect(self._net_done)
            self._worker.failed.connect(self._fail)
            self._worker.finished.connect(self._cleanup)
            self._worker.start()

        def _net_done(self, result):
            plan, proc, devices = result
            self.net_devices = devices
            self.last_net_cmd = plan.shell_preview
            self._fill(self.net_grid, devices)
            if proc.returncode == 127:
                self.net_status.setText(L("nmap non è installato: impossibile cercare.",
                                          "nmap is not installed: cannot search."))
            elif not devices:
                self.net_status.setText(_t("explore.no_devices"))
            else:
                msg = _t("explore.found").replace("{n}", str(len(devices)))
                self.net_status.setText(msg + L("  —  clicca su un dispositivo per i dettagli.",
                                                "  —  click a device for details."))
            self.btn_net_scan.setEnabled(True)
            self.win.log_operation(plan.shell_preview, proc.returncode)

        def scan_bluetooth(self):
            if self._worker is not None:
                return
            self.bt_status.setText(_t("explore.scanning") + f" ({self.bt_seconds.value()} s)")
            self.btn_bt_scan.setEnabled(False)
            self._worker = Worker(ex.scan_bluetooth, self.bt_seconds.value())
            self._worker.done.connect(self._bt_done)
            self._worker.failed.connect(self._fail)
            self._worker.finished.connect(self._cleanup)
            self._worker.start()

        def _bt_done(self, result):
            plan, devices, err = result
            self.bt_devices = devices
            self.last_bt_cmd = plan.shell_preview
            self._fill(self.bt_grid, devices)
            if err:
                self.bt_status.setText(L(f"Bluetooth non disponibile: {err}",
                                         f"Bluetooth unavailable: {err}"))
            elif not devices:
                self.bt_status.setText(_t("explore.no_devices"))
            else:
                msg = _t("explore.found").replace("{n}", str(len(devices)))
                self.bt_status.setText(msg + L("  —  clicca su un dispositivo per i dettagli.",
                                                "  —  click a device for details."))
            self.btn_bt_scan.setEnabled(True)
            self.win.log_operation(plan.shell_preview, 0 if not err else 1)

        def _fail(self, msg):
            QtWidgets.QMessageBox.warning(self, L("Errore", "Error"), msg)
            self.net_status.setText(L("Errore durante la ricerca.", "Error during the search."))
            self.bt_status.setText(L("Errore durante la ricerca.", "Error during the search."))
            self.btn_net_scan.setEnabled(bool(self.networks))
            self.btn_bt_scan.setEnabled(True)

        def _cleanup(self):
            self._worker = None

    # -------------------------------------------- network monitor (bridge)
    class NetMonitorPage(QtWidgets.QWidget):
        """Guided transparent-bridge tap: pick 2 NICs → bridge → capture."""

        def __init__(self, win):
            super().__init__()
            self.win = win
            self.ifaces = []
            self.summary = netmon.TrafficSummary()
            self._worker = None
            self._proc = None
            self._bridge_up = False

            root = QtWidgets.QVBoxLayout(self)
            root.setContentsMargins(28, 24, 28, 16)
            root.addWidget(h1(L("Monitor di rete (bridge trasparente)",
                                "Network monitor (transparent bridge)")))
            root.addWidget(muted(L(
                "Trasforma questo PC con due schede di rete in una «sonda» invisibile: "
                "messo tra il router e il resto della rete, lascia passare tutto il "
                "traffico e te lo mostra. Solo osservazione (passivo), solo su reti tue "
                "o autorizzate.",
                "Turn this PC with two network cards into an invisible “probe”: placed "
                "between the router and the rest of the network, it lets all traffic "
                "through and shows it to you. Observation only (passive), only on your "
                "own or authorized networks.")))

            self.stack = QtWidgets.QStackedWidget()
            root.addWidget(self.stack, 1)
            self.step_lbl = muted("")
            self._build_steps()

            foot = QtWidgets.QHBoxLayout()
            self.btn_back = QtWidgets.QPushButton("‹ " + L("Indietro", "Back"))
            self.btn_back.clicked.connect(lambda: self._goto(self.stack.currentIndex() - 1))
            self.btn_next = QtWidgets.QPushButton(L("Avanti", "Next") + " ›")
            self.btn_next.setDefault(True)
            self.btn_next.clicked.connect(lambda: self._goto(self.stack.currentIndex() + 1))
            self.btn_teardown = QtWidgets.QPushButton(L("Smonta il bridge", "Tear down bridge"))
            self.btn_teardown.clicked.connect(self.teardown)
            foot.addWidget(self.step_lbl, 1)
            foot.addWidget(self.btn_teardown)
            foot.addWidget(self.btn_back)
            foot.addWidget(self.btn_next)
            root.addLayout(foot)
            self._goto(0)

        # ---- step construction
        def _build_steps(self):
            # Step 0 — authorization
            s0 = QtWidgets.QWidget(); l0 = QtWidgets.QVBoxLayout(s0)
            c, cl = card(L("1 · Prima di iniziare", "1 · Before you start"))
            cl.addWidget(muted(L(
                "Questa funzione intercetta il traffico che passa dal PC. Puoi usarla "
                "solo sulla TUA rete o su una rete per cui hai l'autorizzazione. "
                "Vedrai soprattutto «chi parla con chi» e i siti contattati: i contenuti "
                "cifrati (HTTPS) restano illeggibili. È un ascolto passivo: non modifica "
                "nulla.",
                "This feature captures the traffic that passes through the PC. You may "
                "use it only on YOUR network or one you are authorized to monitor. You "
                "will mostly see “who talks to whom” and the sites contacted: encrypted "
                "(HTTPS) contents stay unreadable. It is passive listening: it changes "
                "nothing.")))
            self.chk_auth = QtWidgets.QCheckBox(L(
                "Confermo: è la mia rete o sono autorizzato a monitorarla.",
                "I confirm: this is my network or I am authorized to monitor it."))
            self.chk_auth.toggled.connect(self._refresh_footer)
            cl.addWidget(self.chk_auth)
            l0.addWidget(c); l0.addStretch(1)
            self.stack.addWidget(s0)

            # Step 1 — pick interfaces
            s1 = QtWidgets.QWidget(); l1 = QtWidgets.QVBoxLayout(s1)
            c1, cl1 = card(L("2 · Scegli le due schede di rete", "2 · Choose the two network cards"))
            cl1.addWidget(muted(L(
                "Collega una scheda al router e l'altra al resto della rete (o al "
                "dispositivo da osservare). Scegli le due schede qui sotto.",
                "Connect one card to the router and the other to the rest of the network "
                "(or to the device to observe). Pick the two cards below.")))
            row = QtWidgets.QHBoxLayout()
            self.cmb1 = QtWidgets.QComboBox(); self.cmb1.setMinimumWidth(240)
            self.cmb2 = QtWidgets.QComboBox(); self.cmb2.setMinimumWidth(240)
            self.cmb1.currentIndexChanged.connect(self._refresh_footer)
            self.cmb2.currentIndexChanged.connect(self._refresh_footer)
            row.addWidget(QtWidgets.QLabel("A:")); row.addWidget(self.cmb1)
            row.addSpacing(12)
            row.addWidget(QtWidgets.QLabel("B:")); row.addWidget(self.cmb2)
            row.addStretch(1)
            self.btn_rescan = QtWidgets.QPushButton(L("Rileva schede", "Detect cards"))
            self.btn_rescan.clicked.connect(self.refresh_ifaces)
            row.addWidget(self.btn_rescan)
            cl1.addLayout(row)
            self.if_note = muted("")
            cl1.addWidget(self.if_note)
            l1.addWidget(c1); l1.addStretch(1)
            self.stack.addWidget(s1)

            # Step 2 — create bridge
            s2 = QtWidgets.QWidget(); l2 = QtWidgets.QVBoxLayout(s2)
            c2, cl2 = card(L("3 · Crea il bridge trasparente", "3 · Create the transparent bridge"))
            cl2.addWidget(muted(L(
                "Unisco le due schede in un «ponte» senza indirizzo IP: il PC diventa "
                "invisibile e il traffico passa attraverso. Serve la password di "
                "amministrazione.",
                "I join the two cards into a “bridge” with no IP address: the PC becomes "
                "invisible and traffic flows through it. The admin password is required.")))
            self.btn_bridge = QtWidgets.QPushButton(L("Crea il bridge", "Create the bridge"))
            self.btn_bridge.setMinimumHeight(38)
            self.btn_bridge.clicked.connect(self.create_bridge)
            cl2.addWidget(self.btn_bridge)
            self.bridge_cmd = muted("")
            cl2.addWidget(self.bridge_cmd)
            self.bridge_status = muted("")
            cl2.addWidget(self.bridge_status)
            l2.addWidget(c2); l2.addStretch(1)
            self.stack.addWidget(s2)

            # Step 3 — monitor
            s3 = QtWidgets.QWidget(); l3 = QtWidgets.QVBoxLayout(s3)
            top = QtWidgets.QHBoxLayout()
            self.btn_capture = QtWidgets.QPushButton(L("Avvia la cattura", "Start capture"))
            self.btn_capture.setMinimumHeight(36)
            self.btn_capture.clicked.connect(self.start_capture)
            self.btn_stop = QtWidgets.QPushButton(L("Ferma", "Stop"))
            self.btn_stop.clicked.connect(self.stop_capture)
            self.btn_stop.setEnabled(False)
            top.addWidget(self.btn_capture); top.addWidget(self.btn_stop); top.addStretch(1)
            self.cap_status = muted("")
            top.addWidget(self.cap_status)
            l3.addLayout(top)
            split = QtWidgets.QHBoxLayout()
            dv = QtWidgets.QVBoxLayout()
            dv.addWidget(QtWidgets.QLabel("<b>" + L("Dispositivi sulla rete", "Devices on the network") + "</b>"))
            self.dev_grid = QtWidgets.QListWidget()
            self.dev_grid.setViewMode(QtWidgets.QListView.IconMode)
            self.dev_grid.setIconSize(QtCore.QSize(48, 48))
            self.dev_grid.setGridSize(QtCore.QSize(150, 92))
            self.dev_grid.setResizeMode(QtWidgets.QListView.Adjust)
            self.dev_grid.setMovement(QtWidgets.QListView.Static)
            self.dev_grid.setWordWrap(True)
            dv.addWidget(self.dev_grid, 1)
            sv = QtWidgets.QVBoxLayout()
            sv.addWidget(QtWidgets.QLabel("<b>" + L("Siti contattati", "Sites contacted") + "</b>"))
            self.site_list = QtWidgets.QListWidget()
            sv.addWidget(self.site_list, 1)
            split.addLayout(dv, 3); split.addLayout(sv, 2)
            l3.addLayout(split, 1)
            l3.addWidget(QtWidgets.QLabel("<b>" + L("Chiedi all'AI cosa stai vedendo",
                                                    "Ask the AI what you are seeing") + "</b>"))
            l3.addWidget(AssistantBox(self.win, context_getter=self._ai_context, compact=True))
            self.stack.addWidget(s3)

            # live refresh timer (reads QProcess output buffer)
            self.timer = QtCore.QTimer(self)
            self.timer.setInterval(1200)
            self.timer.timeout.connect(self._drain_and_refresh)

        # ---- navigation / footer
        def _goto(self, idx):
            idx = max(0, min(self.stack.count() - 1, idx))
            if idx == 1 and not self.ifaces:
                self.refresh_ifaces()
            self.stack.setCurrentIndex(idx)
            self._refresh_footer()

        def _refresh_footer(self, *_):
            idx = self.stack.currentIndex()
            n = self.stack.count()
            self.step_lbl.setText(L(f"Passo {idx + 1} di {n}", f"Step {idx + 1} of {n}"))
            self.btn_back.setEnabled(idx > 0)
            self.btn_teardown.setVisible(self._bridge_up)
            ok = True
            if idx == 0:
                ok = self.chk_auth.isChecked()
            elif idx == 1:
                ok = self._selected_pair() is not None
            elif idx == 2:
                ok = self._bridge_up
            self.btn_next.setEnabled(ok and idx < n - 1)
            self.btn_next.setVisible(idx < n - 1)

        # ---- step 1: interfaces
        def refresh_ifaces(self):
            self.ifaces = netmon.list_interfaces()
            for cmb in (self.cmb1, self.cmb2):
                cmb.blockSignals(True); cmb.clear()
                for i in self.ifaces:
                    cmb.addItem(i.title(default_lang()), i)
                cmb.blockSignals(False)
            if len(self.ifaces) >= 2:
                self.cmb2.setCurrentIndex(1)
                self.if_note.setText("")
            else:
                self.if_note.setText(L(
                    "Servono almeno due schede di rete. Collega un secondo adattatore "
                    "(anche USB‑Ethernet) e premi «Rileva schede».",
                    "At least two network cards are required. Connect a second adapter "
                    "(USB‑Ethernet is fine) and press “Detect cards”."))
            self._refresh_footer()

        def _selected_pair(self):
            a = self.cmb1.currentData(); b = self.cmb2.currentData()
            if a is None or b is None or a.name == b.name:
                return None
            return a, b

        # ---- step 2: bridge
        def create_bridge(self):
            pair = self._selected_pair()
            if pair is None or self._worker is not None:
                return
            a, b = pair
            warn = ""
            if a.is_default_route or b.is_default_route:
                warn = L("\n\nATTENZIONE: una delle schede ha la rotta Internet: "
                         "potresti perdere la connessione di gestione.",
                         "\n\nWARNING: one of the cards holds the Internet route: "
                         "you may lose the management connection.")
            argv = netmon.plan_bridge_create(a.name, b.name)
            if QtWidgets.QMessageBox.question(
                    self, L("Crea il bridge", "Create the bridge"),
                    L(f"Unire {a.name} e {b.name} in un bridge trasparente?",
                      f"Join {a.name} and {b.name} into a transparent bridge?")
                    + warn + f"\n\n{' '.join(argv)}") != QtWidgets.QMessageBox.Yes:
                return
            if self.win.mode is not Mode.BEGINNER:
                self.bridge_cmd.setText(f"<code>{html.escape(' '.join(argv))}</code>")
            self.btn_bridge.setEnabled(False)
            self.bridge_status.setText("⏳ " + L("Creazione in corso…", "Creating…"))
            self._worker = Worker(netmon.run_bridge, argv)
            self._worker.done.connect(self._bridge_done)
            self._worker.failed.connect(self._bridge_failed)
            self._worker.finished.connect(self._cleanup)
            self._worker.start()

        def _bridge_done(self, proc):
            rc = getattr(proc, "returncode", 1)
            out = (getattr(proc, "stdout", "") or "") + (getattr(proc, "stderr", "") or "")
            self.win.log_operation("cyberdistro-netbridge create", rc)
            if rc == 0:
                self._bridge_up = True
                self.bridge_status.setStyleSheet("color: #30d158;")
                self.bridge_status.setText("● " + L("Bridge attivo (br0).", "Bridge up (br0)."))
                self._goto(3)
            else:
                self.bridge_status.setStyleSheet("color: #ff3b30;")
                self.bridge_status.setText("✕ " + L("Creazione non riuscita.", "Creation failed."))
                if out.strip():
                    QtWidgets.QMessageBox.warning(self, "bridge", out[-600:])
            self.btn_bridge.setEnabled(True)
            self._refresh_footer()

        def _bridge_failed(self, msg):
            self.bridge_status.setStyleSheet("color: #ff3b30;")
            self.bridge_status.setText("✕ " + msg)
            self.btn_bridge.setEnabled(True)

        # ---- step 3: capture
        def start_capture(self):
            if not netmon.wireshark_available():
                self.cap_status.setText(L("Wireshark non è installato.", "Wireshark is not installed."))
            else:
                try:
                    netmon.run_capture(netmon.plan_wireshark())
                    self.win.log_operation(" ".join(netmon.plan_wireshark()), 0)
                except Exception as e:
                    QtWidgets.QMessageBox.warning(self, "Wireshark", str(e))
            # live visual summary via tshark QProcess (best-effort)
            if netmon.tshark_available():
                self._proc = QtCore.QProcess(self)
                argv = netmon.plan_tshark_summary()
                self._proc.setProgram(argv[0])
                self._proc.setArguments(argv[1:])
                self._proc.start()
                self.timer.start()
                self.cap_status.setText(L("Cattura in corso…", "Capturing…"))
            else:
                self.cap_status.setText(L("tshark non disponibile: nessun riepilogo visuale.",
                                          "tshark unavailable: no visual summary."))
            self.btn_capture.setEnabled(False)
            self.btn_stop.setEnabled(True)

        def stop_capture(self):
            self.timer.stop()
            if self._proc is not None:
                self._proc.kill(); self._proc = None
            self.btn_capture.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.cap_status.setText(L("Cattura fermata.", "Capture stopped."))

        def _drain_and_refresh(self):
            if self._proc is not None:
                try:
                    data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", "replace")
                    if data:
                        self._feed_summary_text(data)
                except Exception:
                    pass
            self._refresh_visual()

        def _ai_context(self):
            devs = self.summary.top_devices(8)
            sites = self.summary.top_sites(12)
            if not devs and not sites:
                return ""
            lines = []
            if devs:
                lines.append(L("Dispositivi:", "Devices:"))
                for d in devs:
                    lines.append(f"  - {d.ip or d.mac}: {d.packets} pkt, "
                                 + ", ".join(sorted(d.sites)[:5]))
            if sites:
                lines.append(L("Siti:", "Sites:") + " " + ", ".join(s.name for s in sites))
            return "\n".join(lines)

        def _feed_summary_text(self, text):
            self.summary.feed(text)

        def _refresh_visual(self):
            self.dev_grid.clear()
            for d in self.summary.top_devices(60):
                label = d.ip or d.mac
                nsites = len(d.sites)
                item = QtWidgets.QListWidgetItem(
                    kind_icon("computer", 48),
                    f"{label}\n{d.packets} pkt · {nsites} " + L("siti", "sites"))
                item.setToolTip((d.mac or "") + "  " + ", ".join(sorted(d.sites)[:8]))
                item.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
                item.setSizeHint(QtCore.QSize(140, 84))
                self.dev_grid.addItem(item)
            self.site_list.clear()
            for s in self.summary.top_sites(100):
                self.site_list.addItem(f"{s.name}   ({s.hits})")

        def teardown(self):
            self.stop_capture()
            try:
                netmon.run_bridge(netmon.plan_bridge_destroy())
            except Exception:
                pass
            self.win.log_operation("cyberdistro-netbridge destroy", 0)
            self._bridge_up = False
            self.bridge_status.setText(L("Bridge rimosso.", "Bridge removed."))
            self._goto(0)

    # ----------------------------------------------------- dashboard page
    class DashboardPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            self.win = win
            self.root = QtWidgets.QVBoxLayout(self)
            self.root.setContentsMargins(28, 24, 28, 24)
            self.body = None
            self.rebuild()

        def rebuild(self):
            if self.body is not None:
                self.body.setParent(None)
                self.body.deleteLater()
            self.body = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(self.body)
            lay.setContentsMargins(0, 0, 0, 0)
            self.root.addWidget(self.body)
            if self.win.mode is Mode.BEGINNER:
                self._beginner(lay)
            else:
                self._pro(lay)

        def _tile(self, icon_name, glyph, title, text, slot):
            b = QtWidgets.QToolButton()
            b.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
            icon = QtGui.QIcon.fromTheme(icon_name)
            if icon.isNull():
                pm = QtGui.QPixmap(72, 72); pm.fill(QtCore.Qt.transparent)
                p = QtGui.QPainter(pm); p.setRenderHint(QtGui.QPainter.Antialiasing)
                p.setBrush(QtGui.QColor("#0a84ff")); p.setPen(QtCore.Qt.NoPen)
                p.drawRoundedRect(0, 0, 72, 72, 18, 18)
                f = p.font(); f.setPixelSize(36); p.setFont(f)
                p.setPen(QtGui.QColor("white")); p.drawText(pm.rect(), QtCore.Qt.AlignCenter, glyph)
                p.end(); icon = QtGui.QIcon(pm)
            b.setIcon(icon); b.setIconSize(QtCore.QSize(72, 72))
            b.setText(title); b.setToolTip(text)
            b.setMinimumSize(200, 150); b.setMaximumHeight(230)
            b.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
            b.setStyleSheet("QToolButton { font-size: 15px; font-weight: 600; border: 1px solid palette(midlight);"
                            " border-radius: 16px; background: palette(base); padding: 12px; }"
                            "QToolButton:hover { background: palette(alternate-base); }")
            b.clicked.connect(slot)
            wrap = QtWidgets.QWidget(); wl = QtWidgets.QVBoxLayout(wrap)
            wl.setContentsMargins(0, 0, 0, 0); wl.addWidget(b)
            d = muted(text); d.setAlignment(QtCore.Qt.AlignHCenter); wl.addWidget(d)
            return wrap

        def _beginner(self, lay):
            lay.addWidget(h1(L("Benvenuto in CyberDistro", "Welcome to CyberDistro")))
            lay.addWidget(muted(L("Scegli cosa vuoi fare. Niente comandi: ogni passo è guidato "
                                  "e ti viene spiegato.",
                                  "Choose what you want to do. No commands: every step is guided "
                                  "and explained.")))
            chips = QtWidgets.QHBoxLayout()
            nets = ex.local_networks()
            st = ps.status()
            bt_ok, _ = ex.bluetooth_available()
            chips.addWidget(chip(L(f"Rete: {nets[0].title}", f"Network: {nets[0].title}") if nets
                                 else L("Rete: non connesso", "Network: not connected"), bool(nets)))
            chips.addWidget(chip(L("Tor: attivo", "Tor: on") if st.tor_socks_open
                                 else L("Tor: non attivo", "Tor: off"), st.tor_socks_open))
            chips.addWidget(chip(L("Kill‑switch: attivo", "Kill‑switch: on") if st.killswitch_loaded
                                 else L("Kill‑switch: spento", "Kill‑switch: off"), st.killswitch_loaded))
            chips.addWidget(chip(L("Bluetooth: disponibile", "Bluetooth: available") if bt_ok
                                 else L("Bluetooth: non disponibile", "Bluetooth: unavailable"), bt_ok))
            chips.addStretch(1)
            lay.addLayout(chips)

            grid = QtWidgets.QGridLayout(); grid.setSpacing(18)
            tiles = [
                ("network-wireless", "📡", L("Esplora la rete", "Explore the network"),
                 L("Scopri chi è collegato al tuo Wi‑Fi e quali dispositivi Bluetooth hai intorno.",
                   "Discover who is on your Wi‑Fi and which Bluetooth devices are around you."),
                 lambda: self.win.go("explore")),
                ("network-wired", "🔌", L("Monitor di rete", "Network monitor"),
                 L("Metti il PC «in mezzo» e guarda il traffico della rete in modo visuale.",
                   "Put the PC “in the middle” and watch the network traffic visually."),
                 lambda: self.win.go("monitor")),
                ("tor", "🧅", L("Naviga anonimo", "Browse anonymously"),
                 L("Apri Tor Browser e controlla lo stato della tua privacy.",
                   "Open Tor Browser and check your privacy status."),
                 lambda: self.win.go("privacy")),
                ("help-contents", "📘", L("Impara", "Learn"),
                 L("Capisci in parole semplici cosa fanno gli strumenti.",
                   "Understand in plain words what the tools do."),
                 lambda: self.win.go("learn")),
            ]
            for i, (ic, gl, ti, tx, slot) in enumerate(tiles):
                grid.addWidget(self._tile(ic, gl, ti, tx, slot), i // 2, i % 2)
            lay.addLayout(grid, 1)
            lay.addWidget(muted(L("Vuoi più controllo? Cambia modalità in basso a sinistra: "
                                  "Professionista mostra i comandi, Esperto sblocca tutto.",
                                  "Want more control? Change mode at the bottom left: "
                                  "Professional shows the commands, Expert unlocks everything.")))

        def _pro(self, lay):
            lay.addWidget(h1(L("Panoramica", "Overview")))
            lay.addWidget(muted(L("Stato reale di questo sistema: strumenti, hardware, Tor.",
                                  "Real status of this system: tools, hardware, Tor.")))
            rep = system_report()
            cat = self.win.catalog
            installed = sum(1 for tl in cat.all_tools() if tl.status().installed)
            total = sum(1 for _ in cat.all_tools())
            grid = QtWidgets.QGridLayout()
            tiles = [(L("Strumenti installati", "Tools installed"), f"{installed}/{total}"),
                     (L("Interfacce Wi‑Fi", "Wi‑Fi interfaces"),
                      ", ".join(rep.get("wifi", {}).keys()) or L("nessuna", "none")),
                     (L("Tor installato", "Tor installed"),
                      L("sì", "yes") if rep.get("tor_installed") else L("no", "no")),
                     (L("Tor Browser", "Tor Browser"),
                      L("incluso", "included") if rep.get("tor_browser_present")
                      else L("non incluso", "not included"))]
            for i, (ti, val) in enumerate(tiles):
                c, cl = card(ti)
                cl.addWidget(QtWidgets.QLabel(f"<h2 style='margin:0'>{html.escape(str(val))}</h2>"))
                grid.addWidget(c, i // 2, i % 2)
            lay.addLayout(grid)
            import json
            txt = QtWidgets.QPlainTextEdit(); txt.setReadOnly(True)
            txt.setPlainText(json.dumps(rep, indent=2, ensure_ascii=False))
            lay.addWidget(txt, 1)

    # ------------------------------------------------------- catalog page
    class CatalogPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1(L("Strumenti", "Tools")))
            lay.addWidget(muted(L("Organizzati per obiettivo. «Guidato» = esiste un percorso "
                                  "passo-passo nel Security Center.",
                                  "Organized by goal. “Guided” = there is a step-by-step flow "
                                  "in the Security Center.")))
            tree = QtWidgets.QTreeWidget()
            tree.setHeaderLabels([L("Strumento", "Tool"), L("Attività", "Activity"),
                                  L("Installato", "Installed"), L("Guidato", "Guided")])
            yes, no = L("sì", "yes"), L("no", "no")
            for c in win.catalog.categories:
                top = QtWidgets.QTreeWidgetItem([c.title_it])
                for tl in c.tools:
                    st = tl.status()
                    QtWidgets.QTreeWidgetItem(top, [tl.name, tl.activity.value,
                                                    yes if st.installed else no,
                                                    yes if tl.has_wrapper else "—"])
                tree.addTopLevelItem(top)
            tree.expandAll()
            tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
            lay.addWidget(tree, 1)

    # ------------------------------------------------------- privacy page
    class PrivacyPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            self.win = win
            self.PROFILES = [
                ("standard", L("Privacy Standard", "Standard privacy"),
                 L("Connessione diretta; nessun kill‑switch.", "Direct connection; no kill‑switch.")),
                ("tor", L("Anonimato Tor", "Tor anonymity"),
                 L("Kill‑switch fail‑closed: fuori da Tor non esce nulla.",
                   "Fail‑closed kill‑switch: nothing leaves outside Tor.")),
                ("hardened", L("Privacy Rafforzata", "Hardened privacy"),
                 L("Come Tor, con restrizioni in uscita aggiuntive.",
                   "Like Tor, with additional egress restrictions."))]
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1(L("Privacy e anonimato", "Privacy & anonymity")))
            lay.addWidget(muted(_t("privacy.no_guarantee")))
            self.chips = QtWidgets.QHBoxLayout()
            lay.addLayout(self.chips)

            c, cl = card(L("Modalità", "Mode"))
            row = QtWidgets.QHBoxLayout()
            for key, title, desc in self.PROFILES:
                b = QtWidgets.QPushButton(title); b.setToolTip(desc); b.setMinimumHeight(40)
                b.clicked.connect(lambda _=False, k=key, ti=title: self.switch(k, ti))
                row.addWidget(b)
            cl.addLayout(row)
            cl.addWidget(muted(L("Il cambio di modalità richiede la password di amministrazione "
                                 "(pkexec) ed è sempre esplicito: nessun cambio silenzioso.",
                                 "Switching mode requires the admin password (pkexec) and is "
                                 "always explicit: no silent change.")))
            lay.addWidget(c)

            c2, cl2 = card("Tor Browser")
            tb = QtWidgets.QPushButton(L("Apri Tor Browser", "Open Tor Browser"))
            tb.setMinimumHeight(40); tb.clicked.connect(self.open_tor_browser)
            cl2.addWidget(tb)
            cl2.addWidget(muted(L("Tor Browser ufficiale, verificato con firma GPG in fase di build. "
                                  "Non viene modificato.",
                                  "Official Tor Browser, GPG-verified at build time. It is not modified.")))
            lay.addWidget(c2)

            self.out = QtWidgets.QPlainTextEdit(); self.out.setReadOnly(True)
            lay.addWidget(self.out, 1)
            self.refresh()

        def refresh(self):
            while self.chips.count():
                it = self.chips.takeAt(0)
                if it.widget():
                    it.widget().deleteLater()
            st = ps.status()
            self.chips.addWidget(chip(L("Tor installato", "Tor installed") if st.tor_installed
                                      else L("Tor non installato", "Tor not installed"), st.tor_installed))
            self.chips.addWidget(chip(L(f"SOCKS Tor aperto ({st.socks_port})", f"Tor SOCKS open ({st.socks_port})")
                                      if st.tor_socks_open else L("Tor non in ascolto", "Tor not listening"),
                                      st.tor_socks_open))
            self.chips.addWidget(chip(L("Kill‑switch attivo", "Kill‑switch on") if st.killswitch_loaded
                                      else L("Kill‑switch spento", "Kill‑switch off"), st.killswitch_loaded))
            self.chips.addWidget(chip("DNS: " + (", ".join(st.dns_resolvers) or "n/d"), True))
            self.chips.addStretch(1)
            lines = [L("Stato osservato:", "Observed status:")] + [f"  • {w}" for w in st.warnings] + \
                    ["", L("Limiti da conoscere:", "Limits to know:")] + [f"  • {l}" for l in st.limits]
            self.out.setPlainText("\n".join(lines))

        def switch(self, key, title):
            if not shutil.which("pkexec"):
                QtWidgets.QMessageBox.warning(self, title, L("pkexec non disponibile su questo sistema.",
                                                             "pkexec not available on this system."))
                return
            cli = shutil.which("privacy-mode") or "/usr/local/sbin/privacy-mode"
            if not os.path.exists(cli):
                QtWidgets.QMessageBox.warning(self, title, L("privacy-mode non installato in questa immagine.",
                                                             "privacy-mode not installed in this image."))
                return
            if QtWidgets.QMessageBox.question(
                    self, title, L(f"Passare a «{title}»?", f"Switch to “{title}”?")
                    + f"\n\npkexec {cli} {key}") != QtWidgets.QMessageBox.Yes:
                return
            try:
                p = subprocess.run(["pkexec", cli, key], capture_output=True, text=True,
                                   timeout=120, check=False)
                self.out.setPlainText((p.stdout or "") + (p.stderr or ""))
            except Exception as e:
                self.out.setPlainText(f"Error: {e}")
            self.refresh()
            self.win.log_operation(f"pkexec {cli} {key}", 0)

        def open_tor_browser(self):
            launcher = "/usr/local/bin/cyberdistro-tor-browser"
            if not os.path.exists(launcher):
                launcher = "/opt/tor-browser/Browser/start-tor-browser"
            if not os.path.exists(launcher):
                QtWidgets.QMessageBox.information(
                    self, "Tor Browser", L("Tor Browser non è incluso in questa immagine. "
                                           "Scaricalo e verificalo da torproject.org.",
                                           "Tor Browser is not included in this image. "
                                           "Download and verify it from torproject.org."))
                return
            subprocess.Popen([launcher], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # --------------------------------------------------------- learn page
    class LearnPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1(L("Impara", "Learn")))
            lay.addWidget(muted(L("Che cosa fa ogni strumento, quando serve e cosa ti serve per usarlo.",
                                  "What each tool does, when it helps and what you need to use it.")))
            browser = QtWidgets.QTextBrowser()
            parts = ["<style>h3{margin-bottom:2px} p{margin-top:2px}</style>"]
            wf = L("Cosa fa:", "What it does:")
            wn = L("Quando:", "When:")
            pm = L("Permessi:", "Permissions:")
            for c in win.catalog.categories:
                parts.append(f"<h2>{html.escape(c.title_it)}</h2><p><i>{html.escape(c.goal_it)}</i></p>")
                for tl in c.tools:
                    d = tl.docs
                    parts.append(f"<h3>{html.escape(tl.name)}</h3>"
                                 f"<p><b>{wf}</b> {html.escape(d.get('what_it_does', ''))}<br>"
                                 f"<b>{wn}</b> {html.escape(d.get('when', ''))}<br>"
                                 f"<b>{pm}</b> {html.escape(d.get('permissions', ''))}</p>")
            browser.setHtml("".join(parts))
            lay.addWidget(browser, 1)

    class AssistantPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1(L("Assistente AI", "AI assistant")))
            lay.addWidget(muted(L(
                "Fai una domanda sulla sicurezza, sul Monitor di rete, sulla privacy o su "
                "come usare CyberDistro. Tutto resta sul tuo computer: nessun account, "
                "nessun dato inviato online.",
                "Ask a question about security, the Network Monitor, privacy or how to use "
                "CyberDistro. Everything stays on your computer: no account, no data sent "
                "online.")))
            ok, _, _ = ai.available()
            lay.addWidget(chip(L("Modello AI locale attivo", "Local AI model active") if ok
                               else L("Nessun modello locale: risposte di base",
                                      "No local model: basic answers"), ok))
            lay.addWidget(AssistantBox(win), 1)

    class CliBackedPage(QtWidgets.QWidget):
        def __init__(self, title, cmd_hint):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1(title))
            lay.addWidget(muted(
                L(f"In questa versione alpha la gestione di «{title}» è disponibile dalla riga di "
                  f"comando con lo stesso motore della GUI:",
                  f"In this alpha, “{title}” is available from the command line with the same "
                  f"engine as the GUI:") + f"<br><code>{html.escape(cmd_hint)}</code>"))
            lay.addStretch(1)

    # ----------------------------------------------- on-demand app sections
    def appstore_icon(section_icon: str, gui: bool, size: int = 40):
        if QtGui.QIcon.hasThemeIcon(section_icon):
            return QtGui.QIcon.fromTheme(section_icon)
        pm = QtGui.QPixmap(size, size); pm.fill(QtCore.Qt.transparent)
        p = QtGui.QPainter(pm); p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setBrush(QtGui.QColor("#0a84ff" if gui else "#8e8e93")); p.setPen(QtCore.Qt.NoPen)
        p.drawRoundedRect(0, 0, size, size, 10, 10)
        f = p.font(); f.setPixelSize(int(size * 0.5)); p.setFont(f)
        p.setPen(QtGui.QColor("white")); p.drawText(pm.rect(), QtCore.Qt.AlignCenter, "🖥" if gui else "⌨")
        p.end()
        return QtGui.QIcon(pm)

    class AppCard(QtWidgets.QFrame):
        def __init__(self, app, section_icon, win):
            super().__init__()
            self.app = app; self.win = win; self._worker = None
            self.setObjectName("Card")
            self.setStyleSheet("#Card { background: palette(base); border: 1px solid palette(midlight);"
                               " border-radius: 14px; }")
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(16, 14, 16, 14); lay.setSpacing(6)
            head = QtWidgets.QHBoxLayout()
            ic = QtWidgets.QLabel(); ic.setPixmap(appstore_icon(section_icon, app.gui, 40).pixmap(40, 40))
            head.addWidget(ic)
            tt = QtWidgets.QVBoxLayout(); tt.setSpacing(0)
            tt.addWidget(QtWidgets.QLabel(f"<b style='font-size:15px'>{html.escape(app.name)}</b>"))
            badge = _t("app.gui_badge") if app.gui else _t("app.cli_badge")
            bcol = "#0a84ff" if app.gui else "#8e8e93"
            tt.addWidget(QtWidgets.QLabel(f"<span style='color:{bcol}'>● {html.escape(badge)}</span>"))
            head.addLayout(tt, 1)
            self.btn = QtWidgets.QPushButton()
            self.btn.setMinimumWidth(150); self.btn.setMinimumHeight(34)
            self.btn.clicked.connect(self._on_click)
            head.addWidget(self.btn, 0, QtCore.Qt.AlignTop)
            lay.addLayout(head)
            lay.addWidget(muted(app.desc))
            use = QtWidgets.QLabel(f"<b>{html.escape(_t('app.use_label'))}:</b> {html.escape(app.use)}")
            use.setWordWrap(True); lay.addWidget(use)
            if app.note:
                lay.addWidget(muted("ⓘ " + app.note))
            self.status = muted(""); lay.addWidget(self.status)
            self._refresh_button()

        def _refresh_button(self):
            if self.app.installed():
                self.btn.setText(_t("app.open"))
                self.status.setText("● " + _t("app.installed"))
                self.status.setStyleSheet("color: #30d158;")
            else:
                self.btn.setText(_t("app.install")); self.status.setText("")
            self.btn.setEnabled(True)

        def _on_click(self):
            self._launch() if self.app.installed() else self._install()

        def _launch(self):
            try:
                appstore.run_launch(self.app)
                self.win.log_operation(" ".join(self.app.launch_argv()), 0)
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, self.app.name, L(f"Avvio non riuscito: {e}",
                                                                     f"Launch failed: {e}"))

        def _install(self):
            if self._worker is not None:
                return
            self.btn.setEnabled(False)
            self.status.setStyleSheet("color: palette(mid);")
            self.status.setText("⏳ " + _t("app.installing"))
            self._worker = Worker(appstore.run_install, self.app)
            self._worker.done.connect(self._installed)
            self._worker.failed.connect(self._failed)
            self._worker.finished.connect(self._cleanup)
            self._worker.start()

        def _installed(self, proc):
            rc = getattr(proc, "returncode", 1)
            self.win.log_operation(" ".join(self.app.install_argv()), rc)
            if rc == 0 and self.app.installed():
                self._refresh_button(); self._launch()
            else:
                tail = (getattr(proc, "stderr", "") or getattr(proc, "stdout", "") or "")[-400:]
                self.status.setStyleSheet("color: #ff3b30;")
                self.status.setText("✕ " + _t("app.install_failed")
                                    + (" " + _t("app.needs_net") if self.app.source != "pip" else ""))
                if tail.strip():
                    QtWidgets.QMessageBox.warning(self, self.app.name, tail)
                self.btn.setEnabled(True)

        def _failed(self, msg):
            self.status.setStyleSheet("color: #ff3b30;")
            self.status.setText("✕ " + _t("app.install_failed"))
            QtWidgets.QMessageBox.warning(self, self.app.name, msg)
            self.btn.setEnabled(True)

        def _cleanup(self):
            self._worker = None

    class AppStorePage(QtWidgets.QWidget):
        def __init__(self, section, win):
            super().__init__()
            self.section = section
            root = QtWidgets.QVBoxLayout(self)
            root.setContentsMargins(28, 24, 28, 16)
            root.addWidget(h1(section.title))
            root.addWidget(muted(section.intro))
            root.addWidget(muted(L("Le applicazioni non sono preinstallate (così l'immagine resta "
                                   "leggera): scegli quelle che ti servono e premi «",
                                   "The applications are not pre-installed (so the image stays "
                                   "light): pick the ones you need and press “")
                                 + _t("app.install")
                                 + L("». Serve una connessione a Internet.",
                                     "”. An internet connection is required.")))
            scroll = QtWidgets.QScrollArea(); scroll.setWidgetResizable(True)
            scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
            inner = QtWidgets.QWidget(); col = QtWidgets.QVBoxLayout(inner)
            col.setContentsMargins(0, 8, 8, 0); col.setSpacing(12)
            self.cards = []
            for app in section.apps:
                c = AppCard(app, section.icon, win)
                self.cards.append(c); col.addWidget(c)
            col.addStretch(1)
            scroll.setWidget(inner); root.addWidget(scroll, 1)

    # ---------------------------------------------------------- main window
    PAGE_DEFS = [  # key, beginner-visible
        ("explore", True), ("dashboard", True), ("monitor", True),
        ("forensics", True), ("reversing", True), ("assistant", True),
        ("catalog", False), ("privacy", True), ("projects", False),
        ("reports", False), ("learn", True),
    ]

    def page_label(key):
        return {
            "explore": _t("nav.explore"),
            "dashboard": L("Panoramica", "Overview"),
            "monitor": L("Monitor di rete", "Network monitor"),
            "forensics": _t("nav.forensics"),
            "reversing": _t("nav.reversing"),
            "assistant": L("Assistente AI", "AI assistant"),
            "catalog": L("Strumenti", "Tools"),
            "privacy": "Privacy",
            "projects": L("Progetti", "Projects"),
            "reports": L("Report", "Reports"),
            "learn": L("Impara", "Learn"),
        }[key]

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"CyberDistro — Security Center {__version__}")
            self.resize(1180, 760)
            self.mode = Mode.parse(os.environ.get("CYBERDISTRO_MODE"), Mode.BEGINNER)
            self.catalog = Catalog.load()
            self.store = appstore.AppStore.load()
            self.operations = []

            central = QtWidgets.QWidget(); self.setCentralWidget(central)
            layout = QtWidgets.QHBoxLayout(central)
            layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)

            side = QtWidgets.QWidget(); side.setObjectName("Sidebar"); side.setFixedWidth(230)
            side.setStyleSheet("#Sidebar { background: palette(alternate-base); border-right: 1px solid palette(midlight); }")
            sl = QtWidgets.QVBoxLayout(side); sl.setContentsMargins(10, 14, 10, 14)
            sl.addWidget(QtWidgets.QLabel("<b style='font-size:16px'>CyberDistro</b><br>"
                                          "<span style='color:gray'>Security Center</span>"))
            sl.addSpacing(8)
            self.nav = QtWidgets.QListWidget(); self.nav.setFrameShape(QtWidgets.QFrame.NoFrame)
            self.nav.setStyleSheet("QListWidget { background: transparent; font-size: 14px; }"
                                   "QListWidget::item { padding: 9px 12px; border-radius: 9px; }"
                                   "QListWidget::item:selected { background: palette(highlight); color: palette(highlighted-text); }")
            self.nav.setIconSize(QtCore.QSize(20, 20))
            self.nav.currentRowChanged.connect(self._nav_changed)
            sl.addWidget(self.nav, 1)
            sl.addWidget(QtWidgets.QLabel(L("Modalità", "Mode")))
            self.mode_combo = QtWidgets.QComboBox()
            for m in Mode:
                self.mode_combo.addItem(mode_label(m), m)
            self.mode_combo.setCurrentIndex(list(Mode).index(self.mode))
            self.mode_combo.currentIndexChanged.connect(self._mode_changed)
            sl.addWidget(self.mode_combo)

            # Keyboard layout — independent of the UI language; applies at runtime.
            sl.addSpacing(6)
            sl.addWidget(QtWidgets.QLabel(L("Tastiera", "Keyboard")))
            self.kbd_combo = QtWidgets.QComboBox()
            for code, label in kbd.layouts():
                self.kbd_combo.addItem(f"{label} ({code})", code)
            cur = kbd.current_layout()
            for i in range(self.kbd_combo.count()):
                if self.kbd_combo.itemData(i) == cur:
                    self.kbd_combo.setCurrentIndex(i)
                    break
            self.kbd_combo.currentIndexChanged.connect(self._kbd_changed)
            sl.addWidget(self.kbd_combo)
            layout.addWidget(side)

            self.stack = QtWidgets.QStackedWidget(); layout.addWidget(self.stack, 1)
            self.pages = {
                "explore": ExplorePage(self),
                "dashboard": DashboardPage(self),
                "monitor": NetMonitorPage(self),
                "forensics": AppStorePage(self.store.section("forensics"), self),
                "reversing": AppStorePage(self.store.section("reversing"), self),
                "assistant": AssistantPage(self),
                "catalog": CatalogPage(self),
                "privacy": PrivacyPage(self),
                "projects": CliBackedPage(L("Progetti", "Projects"),
                                          "cyberdistro-sc project new NAME --owner WHO --scope 192.168.1.0/24"),
                "reports": CliBackedPage(L("Report", "Reports"), "cyberdistro-sc report NAME --format html"),
                "learn": LearnPage(self),
            }
            for key, _ in PAGE_DEFS:
                self.stack.addWidget(self.pages[key])
            self._rebuild_nav()
            self.go("explore" if self.mode is Mode.BEGINNER else "dashboard")

        def _rebuild_nav(self):
            self.nav.blockSignals(True); self.nav.clear()
            icons = {"explore": "network-wireless", "dashboard": "dashboard-show",
                     "monitor": "network-wired", "forensics": "drive-harddisk",
                     "reversing": "applications-development", "assistant": "help-faq",
                     "catalog": "applications-utilities",
                     "privacy": "security-high", "projects": "folder",
                     "reports": "x-office-document", "learn": "help-contents"}
            for key, beginner_ok in PAGE_DEFS:
                if self.mode is Mode.BEGINNER and not beginner_ok:
                    continue
                it = QtWidgets.QListWidgetItem(QtGui.QIcon.fromTheme(icons[key]), page_label(key))
                it.setData(QtCore.Qt.UserRole, key)
                self.nav.addItem(it)
            self.nav.blockSignals(False)

        def go(self, key):
            self.stack.setCurrentWidget(self.pages[key])
            for i in range(self.nav.count()):
                if self.nav.item(i).data(QtCore.Qt.UserRole) == key:
                    self.nav.blockSignals(True); self.nav.setCurrentRow(i); self.nav.blockSignals(False)
                    break

        def _nav_changed(self, row):
            if row < 0:
                return
            self.stack.setCurrentWidget(self.pages[self.nav.item(row).data(QtCore.Qt.UserRole)])

        def _mode_changed(self, idx):
            self.mode = list(Mode)[idx]
            current = self.stack.currentWidget()
            self.pages["dashboard"].rebuild()
            self._rebuild_nav()
            key = next(k for k, p in self.pages.items() if p is current)
            beginner_ok = dict(PAGE_DEFS)[key]
            if self.mode is Mode.BEGINNER and not beginner_ok:
                key = "explore"
            self.go(key)

        def _kbd_changed(self, idx):
            code = self.kbd_combo.itemData(idx)
            if not code:
                return
            try:
                kbd.apply_layout(code)
                self.log_operation(" ".join(kbd.plan_set(code)), 0)
            except Exception as e:
                self.statusBar().showMessage(L(f"Tastiera: {e}", f"Keyboard: {e}"), 6000)

        def log_operation(self, command, returncode):
            self.operations.append((command, returncode))
            if self.mode is not Mode.BEGINNER:
                self.statusBar().showMessage(L(f"Eseguito: {command}  (exit {returncode})",
                                               f"Ran: {command}  (exit {returncode})"), 15000)
            else:
                self.statusBar().showMessage(L("Operazione completata.", "Operation complete."), 5000)

        def verify_file(self):
            from ..tools import forensic_hash as fh
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, L("Scegli il file da verificare",
                                                                    "Choose the file to verify"))
            if not path:
                return
            try:
                res = fh.compute(path, ("sha256",))
                digest = res.hashes["sha256"]
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, L("Verifica file", "Verify file"), f"Error: {e}")
                return
            QtWidgets.QMessageBox.information(
                self, L("Impronta del file", "File fingerprint"),
                f"<b>{html.escape(os.path.basename(path))}</b><br><br>SHA‑256:<br><code>{digest}</code><br><br>"
                + L("Se l'impronta coincide con quella pubblicata da chi ti ha dato il file, "
                    "il file non è stato modificato.",
                    "If the fingerprint matches the one published by whoever gave you the file, "
                    "the file has not been modified."))

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(argv or sys.argv)
    app.setApplicationName("CyberDistro Security Center")
    app.setDesktopFileName("cyberdistro-security-center")
    win = MainWindow()
    return app, win


def run() -> int:  # pragma: no cover - requires a display
    app, win = build_app()
    win.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
