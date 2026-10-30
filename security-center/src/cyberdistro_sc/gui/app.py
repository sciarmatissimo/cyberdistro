"""CyberDistro — Security Center GUI (PySide6).

Presentation layer only: every action calls into ``cyberdistro_sc.core`` or
``cyberdistro_sc.tools``. The GUI never computes results itself and, in the
Professional/Expert modes, always shows the underlying command before running
it (honesty + reproducibility).

Pages (left sidebar):
  * Esplora      — beginner-first, visual: who is on the network / Bluetooth,
                   one tile per device, click → details.
  * Panoramica   — Beginner: big action tiles; Pro/Expert: system report.
  * Strumenti    — catalog by operational goal (Pro/Expert).
  * Privacy      — truthful Tor/kill-switch posture, profile switch (pkexec),
                   Tor Browser launcher.
  * Progetti / Report — Pro/Expert (CLI-backed; GUI minimal in this alpha).
  * Impara       — plain-language explanations.

The mode switch (Principiante / Professionista / Esperto) is reversible and only
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
from ..i18n import t as _t
from ..tools import explore as ex
from ..tools import privacy_status as ps
from .. import __version__

MODE_LABELS = {Mode.BEGINNER: "Principiante", Mode.PROFESSIONAL: "Professionista",
               Mode.EXPERT: "Esperto"}

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

# Plain-language explanation of each device kind for beginners.
KIND_EXPLAIN_IT = {
    "self": "È il computer che stai usando adesso.",
    "router": "È il dispositivo che collega la tua rete a Internet (modem/router). "
              "Di solito è fornito dall'operatore o acquistato da te.",
    "computer": "Un computer fisso o portatile collegato alla tua rete.",
    "phone": "Uno smartphone o un tablet collegato alla rete.",
    "printer": "Una stampante o uno scanner di rete.",
    "tv": "Una smart TV o un lettore multimediale.",
    "camera": "Una videocamera o telecamera connessa.",
    "audio": "Cuffie, auricolari o altoparlanti.",
    "input": "Tastiera, mouse o controller.",
    "wearable": "Smartwatch o braccialetto fitness.",
    "iot": "Un dispositivo «smart» (presa, lampadina, sensore, assistente vocale…).",
    "unknown": "Non è stato possibile riconoscere il tipo: è comunque un dispositivo "
               "presente. Se non lo riconosci, verifica chi lo possiede.",
}


def _require_qt():
    try:
        from PySide6 import QtWidgets, QtCore, QtGui  # noqa: F401
        return QtWidgets, QtCore, QtGui
    except Exception as e:  # pragma: no cover - environment dependent
        raise SystemExit(
            "PySide6 non è installato. Installa il pacchetto "
            "'python3-pyside6.*' oppure `pip install PySide6`.\n"
            f"Dettaglio: {e}"
        )


def build_app(argv=None):  # pragma: no cover - requires Qt
    """Create (QApplication, MainWindow) without entering the event loop.

    Separated from run() so the smoke test can build the whole UI offscreen,
    exercise the pages and take screenshots without blocking.
    """
    QtWidgets, QtCore, QtGui = _require_qt()

    # ------------------------------------------------------------ helpers
    def kind_icon(kind: str, size: int = 64) -> "QtGui.QIcon":
        icon = QtGui.QIcon.fromTheme(ex.icon_for(kind))
        if not icon.isNull():
            return icon
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
        lbl = QtWidgets.QLabel(f"<h1 style='margin:0'>{html.escape(text)}</h1>")
        return lbl

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
            except Exception as e:  # surfaced to the UI, never swallowed
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
            tcol.addWidget(muted(ex.label_for(dev.kind)))
            head.addLayout(tcol, 1)
            lay.addLayout(head)

            expl = muted(KIND_EXPLAIN_IT.get(dev.kind, ""))
            lay.addWidget(expl)

            rows = []
            if dev.source == "network":
                rows.append(("Indirizzo IP", dev.address))
                rows.append(("Nome", dev.name or "non disponibile"))
            else:
                rows.append(("Indirizzo Bluetooth", dev.address))
                rows.append(("Nome", dev.name or "non annunciato"))
            rows.append(("Indirizzo fisico (MAC)", dev.mac or "non disponibile"))
            rows.append(("Produttore", dev.vendor or (
                "non identificabile (indirizzo casuale)"
                if dev.details.get("mac_random") == "sì" else "non disponibile")))
            for k, v in dev.details.items():
                if k == "mac_random":
                    continue
                rows.append((k.capitalize(), str(v)))

            table = QtWidgets.QTableWidget(len(rows), 2)
            table.setHorizontalHeaderLabels(["Informazione", "Valore"])
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
                lay.addWidget(muted(f"Comando eseguito: <code>{html.escape(command)}</code>"))
            if mode is Mode.BEGINNER and dev.source == "network":
                lay.addWidget(muted(
                    "Vuoi saperne di più su questo dispositivo? Passa alla modalità "
                    "Professionista e usa «Inventario di rete (Nmap)» su un progetto "
                    "con ambito autorizzato."))
            btns = QtWidgets.QDialogButtonBox()
            btns.addButton("Chiudi", QtWidgets.QDialogButtonBox.RejectRole)
            btns.rejected.connect(self.reject)
            btns.accepted.connect(self.accept)
            lay.addWidget(btns)

    # ------------------------------------------------------- explore page
    class ExplorePage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            self.win = win
            self.networks: list[ex.LocalNetwork] = []
            self.net_devices: list[ex.Device] = []
            self.bt_devices: list[ex.Device] = []
            self.last_net_cmd = ""
            self.last_bt_cmd = ""
            self._confirmed: set[str] = set()
            self._worker = None

            root = QtWidgets.QVBoxLayout(self)
            root.setContentsMargins(28, 24, 28, 24)
            root.addWidget(h1(_t("explore.title")))
            root.addWidget(muted(_t("explore.subtitle")))

            self.tabs = QtWidgets.QTabWidget()
            root.addWidget(self.tabs, 1)

            # --- network tab
            nt = QtWidgets.QWidget()
            nl = QtWidgets.QVBoxLayout(nt)
            bar = QtWidgets.QHBoxLayout()
            self.net_combo = QtWidgets.QComboBox()
            self.net_combo.setMinimumWidth(260)
            bar.addWidget(QtWidgets.QLabel("Rete:"))
            bar.addWidget(self.net_combo)
            self.btn_refresh = QtWidgets.QPushButton("Aggiorna reti")
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
            self.net_grid = self._make_grid(self.net_devices, lambda: self.last_net_cmd)
            nl.addWidget(self.net_grid, 1)
            self.tabs.addTab(nt, _t("explore.network_tab"))

            # --- bluetooth tab
            bt = QtWidgets.QWidget()
            bl = QtWidgets.QVBoxLayout(bt)
            bbar = QtWidgets.QHBoxLayout()
            bbar.addWidget(QtWidgets.QLabel("Durata ascolto:"))
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
            self.bt_grid = self._make_grid(self.bt_devices, lambda: self.last_bt_cmd)
            bl.addWidget(self.bt_grid, 1)
            self.tabs.addTab(bt, _t("explore.bluetooth_tab"))

            self.refresh_networks()
            ok, why = ex.bluetooth_available()
            self.bt_status.setText("Pronto: premi «Cerca dispositivi»." if ok
                                   else f"Bluetooth non disponibile: {why}")
            self.btn_bt_scan.setEnabled(ok)

        def _make_grid(self, store, cmd_getter):
            grid = QtWidgets.QListWidget()
            grid.setViewMode(QtWidgets.QListView.IconMode)
            grid.setIconSize(QtCore.QSize(72, 72))
            grid.setGridSize(QtCore.QSize(184, 140))
            grid.setResizeMode(QtWidgets.QListView.Adjust)
            grid.setMovement(QtWidgets.QListView.Static)
            grid.setSpacing(10)
            grid.setWordWrap(True)
            grid.setStyleSheet("QListWidget { font-size: 13px; }"
                               "QListWidget::item { padding: 6px; border-radius: 10px; }"
                               "QListWidget::item:selected { background: palette(highlight); color: palette(highlighted-text); }")

            def open_details(item):
                dev = item.data(QtCore.Qt.UserRole)
                DeviceDialog(dev, self.win.mode, cmd_getter(), self).exec()
            grid.itemClicked.connect(open_details)
            grid.itemActivated.connect(open_details)
            return grid

        def _fill(self, grid, devices):
            grid.clear()
            for d in devices:
                label = d.display_name
                sub = ex.label_for(d.kind)
                item = QtWidgets.QListWidgetItem(kind_icon(d.kind), f"{label}\n{sub}")
                item.setData(QtCore.Qt.UserRole, d)
                item.setToolTip(f"{d.address}" + (f" · {d.vendor}" if d.vendor else ""))
                item.setTextAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
                item.setSizeHint(QtCore.QSize(172, 126))
                grid.addItem(item)

        # ---- network
        def refresh_networks(self):
            self.networks = ex.local_networks()
            self.net_combo.clear()
            for n in self.networks:
                extra = " (ridotta a /24)" if n.capped else ""
                self.net_combo.addItem(f"{n.title} — {n.cidr}{extra}", n)
            if not self.networks:
                self.net_status.setText(_t("explore.no_network"))
                self.btn_net_scan.setEnabled(False)
            else:
                self.net_status.setText("Pronto: premi «Cerca dispositivi».")
                self.btn_net_scan.setEnabled(True)

        def _confirm_network(self, net: ex.LocalNetwork) -> bool:
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
                lay.addWidget(muted(f"Comando: <code>{html.escape(ex.plan_network_scan(net.cidr).shell_preview)}</code>"))
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
                self.net_status.setText("Ricerca annullata: nessuna conferma.")
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
                self.net_status.setText("nmap non è installato: impossibile cercare.")
            elif not devices:
                self.net_status.setText(_t("explore.no_devices"))
            else:
                msg = _t("explore.found").replace("{n}", str(len(devices)))
                self.net_status.setText(msg + "  —  clicca su un dispositivo per i dettagli.")
            self.btn_net_scan.setEnabled(True)
            self.win.log_operation(plan.shell_preview, proc.returncode)

        # ---- bluetooth
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
                self.bt_status.setText(f"Bluetooth non disponibile: {err}")
            elif not devices:
                self.bt_status.setText(_t("explore.no_devices"))
            else:
                msg = _t("explore.found").replace("{n}", str(len(devices)))
                self.bt_status.setText(msg + "  —  clicca su un dispositivo per i dettagli.")
            self.btn_bt_scan.setEnabled(True)
            self.win.log_operation(plan.shell_preview, 0 if not err else 1)

        def _fail(self, msg):
            QtWidgets.QMessageBox.warning(self, "Errore", msg)
            self.net_status.setText("Errore durante la ricerca.")
            self.bt_status.setText("Errore durante la ricerca.")
            self.btn_net_scan.setEnabled(bool(self.networks))
            self.btn_bt_scan.setEnabled(True)

        def _cleanup(self):
            self._worker = None

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
                pm = QtGui.QPixmap(72, 72)
                pm.fill(QtCore.Qt.transparent)
                p = QtGui.QPainter(pm)
                p.setRenderHint(QtGui.QPainter.Antialiasing)
                p.setBrush(QtGui.QColor("#0a84ff"))
                p.setPen(QtCore.Qt.NoPen)
                p.drawRoundedRect(0, 0, 72, 72, 18, 18)
                f = p.font(); f.setPixelSize(36); p.setFont(f)
                p.setPen(QtGui.QColor("white"))
                p.drawText(pm.rect(), QtCore.Qt.AlignCenter, glyph)
                p.end()
                icon = QtGui.QIcon(pm)
            b.setIcon(icon)
            b.setIconSize(QtCore.QSize(72, 72))
            b.setText(title)
            b.setToolTip(text)
            b.setMinimumSize(200, 150)
            b.setMaximumHeight(230)
            b.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
            b.setStyleSheet("QToolButton { font-size: 15px; font-weight: 600; border: 1px solid palette(midlight);"
                            " border-radius: 16px; background: palette(base); padding: 12px; }"
                            "QToolButton:hover { background: palette(alternate-base); }")
            b.clicked.connect(slot)
            wrap = QtWidgets.QWidget()
            wl = QtWidgets.QVBoxLayout(wrap)
            wl.setContentsMargins(0, 0, 0, 0)
            wl.addWidget(b)
            d = muted(text)
            d.setAlignment(QtCore.Qt.AlignHCenter)
            wl.addWidget(d)
            return wrap

        def _beginner(self, lay):
            lay.addWidget(h1("Benvenuto in CyberDistro"))
            lay.addWidget(muted("Scegli cosa vuoi fare. Niente comandi: ogni passo è guidato "
                                "e ti viene spiegato."))
            # status chips
            chips = QtWidgets.QHBoxLayout()
            nets = ex.local_networks()
            st = ps.status()
            bt_ok, _ = ex.bluetooth_available()
            for text, good in (
                (f"Rete: {nets[0].title}" if nets else "Rete: non connesso", bool(nets)),
                ("Tor: attivo" if st.tor_socks_open else "Tor: non attivo", st.tor_socks_open),
                ("Kill‑switch: attivo" if st.killswitch_loaded else "Kill‑switch: spento", st.killswitch_loaded),
                ("Bluetooth: disponibile" if bt_ok else "Bluetooth: non disponibile", bt_ok),
            ):
                c = QtWidgets.QLabel(("● " if good else "○ ") + text)
                c.setStyleSheet(f"padding: 6px 12px; border-radius: 12px; border: 1px solid palette(midlight);"
                                f" color: {'#30d158' if good else 'palette(mid)'};")
                chips.addWidget(c)
            chips.addStretch(1)
            lay.addLayout(chips)

            grid = QtWidgets.QGridLayout()
            grid.setSpacing(18)
            tiles = [
                ("network-wireless", "📡", "Esplora la rete",
                 "Scopri chi è collegato al tuo Wi‑Fi e quali dispositivi Bluetooth hai intorno.",
                 lambda: self.win.go("explore")),
                ("torbrowser", "🧅", "Naviga anonimo",
                 "Apri Tor Browser e controlla lo stato della tua privacy.",
                 lambda: self.win.go("privacy")),
                ("document-encrypt", "🔏", "Verifica un file",
                 "Calcola l'impronta (hash) di un file per sapere se è stato modificato.",
                 self.win.verify_file),
                ("help-contents", "📘", "Impara",
                 "Capisci in parole semplici cosa fanno gli strumenti.",
                 lambda: self.win.go("learn")),
            ]
            for i, (ic, gl, ti, tx, slot) in enumerate(tiles):
                grid.addWidget(self._tile(ic, gl, ti, tx, slot), i // 2, i % 2)
            lay.addLayout(grid, 1)
            lay.addWidget(muted("Vuoi più controllo? Cambia modalità in basso a sinistra: "
                                "Professionista mostra i comandi, Esperto sblocca tutto."))

        def _pro(self, lay):
            lay.addWidget(h1("Panoramica"))
            lay.addWidget(muted("Stato reale di questo sistema: strumenti, hardware, Tor."))
            rep = system_report()
            cat = self.win.catalog
            installed = sum(1 for tl in cat.all_tools() if tl.status().installed)
            total = sum(1 for _ in cat.all_tools())
            grid = QtWidgets.QGridLayout()
            tiles = [("Strumenti installati", f"{installed}/{total}"),
                     ("Interfacce Wi‑Fi", ", ".join(rep.get("wifi", {}).keys()) or "nessuna"),
                     ("Tor installato", "sì" if rep.get("tor_installed") else "no"),
                     ("Tor Browser", "incluso" if rep.get("tor_browser_present") else "non incluso")]
            for i, (ti, val) in enumerate(tiles):
                c, cl = card(ti)
                cl.addWidget(QtWidgets.QLabel(f"<h2 style='margin:0'>{html.escape(str(val))}</h2>"))
                grid.addWidget(c, i // 2, i % 2)
            lay.addLayout(grid)
            import json
            txt = QtWidgets.QPlainTextEdit()
            txt.setReadOnly(True)
            txt.setPlainText(json.dumps(rep, indent=2, ensure_ascii=False))
            lay.addWidget(txt, 1)

    # ------------------------------------------------------- catalog page
    class CatalogPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1("Strumenti"))
            lay.addWidget(muted("Organizzati per obiettivo. «Guidato» = esiste un percorso "
                                "passo-passo nel Security Center."))
            tree = QtWidgets.QTreeWidget()
            tree.setHeaderLabels(["Strumento", "Attività", "Installato", "Guidato"])
            for c in win.catalog.categories:
                top = QtWidgets.QTreeWidgetItem([c.title_it])
                for tl in c.tools:
                    st = tl.status()
                    QtWidgets.QTreeWidgetItem(top, [
                        tl.name, tl.activity.value,
                        "sì" if st.installed else "no",
                        "sì" if tl.has_wrapper else "—"])
                tree.addTopLevelItem(top)
            tree.expandAll()
            tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
            lay.addWidget(tree, 1)

    # ------------------------------------------------------- privacy page
    class PrivacyPage(QtWidgets.QWidget):
        PROFILES = [("standard", "Privacy Standard", "Connessione diretta; nessun kill‑switch."),
                    ("tor", "Anonimato Tor", "Kill‑switch fail‑closed: fuori da Tor non esce nulla."),
                    ("hardened", "Privacy Rafforzata", "Come Tor, con restrizioni in uscita aggiuntive.")]

        def __init__(self, win):
            super().__init__()
            self.win = win
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1("Privacy e anonimato"))
            lay.addWidget(muted(_t("privacy.no_guarantee")))

            self.chips = QtWidgets.QHBoxLayout()
            lay.addLayout(self.chips)

            c, cl = card("Modalità")
            row = QtWidgets.QHBoxLayout()
            for key, title, desc in self.PROFILES:
                b = QtWidgets.QPushButton(title)
                b.setToolTip(desc)
                b.setMinimumHeight(40)
                b.clicked.connect(lambda _=False, k=key, ti=title: self.switch(k, ti))
                row.addWidget(b)
            cl.addLayout(row)
            cl.addWidget(muted("Il cambio di modalità richiede la password di amministrazione "
                               "(pkexec) ed è sempre esplicito: nessun cambio silenzioso."))
            lay.addWidget(c)

            c2, cl2 = card("Tor Browser")
            tb = QtWidgets.QPushButton("Apri Tor Browser")
            tb.setMinimumHeight(40)
            tb.clicked.connect(self.open_tor_browser)
            cl2.addWidget(tb)
            cl2.addWidget(muted("Tor Browser ufficiale, verificato con firma GPG in fase di build. "
                                "Non viene modificato."))
            lay.addWidget(c2)

            self.out = QtWidgets.QPlainTextEdit()
            self.out.setReadOnly(True)
            lay.addWidget(self.out, 1)
            self.refresh()

        def refresh(self):
            while self.chips.count():
                it = self.chips.takeAt(0)
                if it.widget():
                    it.widget().deleteLater()
            st = ps.status()
            for text, good in (
                ("Tor installato" if st.tor_installed else "Tor non installato", st.tor_installed),
                (f"SOCKS Tor aperto ({st.socks_port})" if st.tor_socks_open else "Tor non in ascolto", st.tor_socks_open),
                ("Kill‑switch attivo" if st.killswitch_loaded else "Kill‑switch spento", st.killswitch_loaded),
                ("DNS: " + (", ".join(st.dns_resolvers) or "n/d"), True),
            ):
                lbl = QtWidgets.QLabel(("● " if good else "○ ") + text)
                lbl.setStyleSheet(f"padding: 6px 12px; border-radius: 12px; border: 1px solid palette(midlight);"
                                  f" color: {'#30d158' if good else 'palette(mid)'};")
                self.chips.addWidget(lbl)
            self.chips.addStretch(1)
            lines = ["Stato osservato:"] + [f"  • {w}" for w in st.warnings] + \
                    ["", "Limiti da conoscere:"] + [f"  • {l}" for l in st.limits]
            self.out.setPlainText("\n".join(lines))

        def switch(self, key, title):
            if not shutil.which("pkexec"):
                QtWidgets.QMessageBox.warning(self, title, "pkexec non disponibile su questo sistema.")
                return
            cli = shutil.which("privacy-mode") or "/usr/local/sbin/privacy-mode"
            if not os.path.exists(cli):
                QtWidgets.QMessageBox.warning(self, title, "privacy-mode non installato in questa immagine.")
                return
            if QtWidgets.QMessageBox.question(
                    self, title, f"Passare a «{title}»?\n\nComando: pkexec {cli} {key}") != QtWidgets.QMessageBox.Yes:
                return
            try:
                p = subprocess.run(["pkexec", cli, key], capture_output=True, text=True,
                                   timeout=120, check=False)
                self.out.setPlainText((p.stdout or "") + (p.stderr or ""))
            except Exception as e:
                self.out.setPlainText(f"Errore: {e}")
            self.refresh()
            self.win.log_operation(f"pkexec {cli} {key}", 0)

        def open_tor_browser(self):
            launcher = "/usr/local/bin/cyberdistro-tor-browser"
            if not os.path.exists(launcher):
                launcher = "/opt/tor-browser/Browser/start-tor-browser"
            if not os.path.exists(launcher):
                QtWidgets.QMessageBox.information(
                    self, "Tor Browser", "Tor Browser non è incluso in questa immagine. "
                    "Scaricalo e verificalo da torproject.org.")
                return
            subprocess.Popen([launcher], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # --------------------------------------------------------- learn page
    class LearnPage(QtWidgets.QWidget):
        def __init__(self, win):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1("Impara"))
            lay.addWidget(muted("Che cosa fa ogni strumento, quando serve e cosa ti serve per usarlo."))
            browser = QtWidgets.QTextBrowser()
            parts = ["<style>h3{margin-bottom:2px} p{margin-top:2px}</style>"]
            for c in win.catalog.categories:
                parts.append(f"<h2>{html.escape(c.title_it)}</h2><p><i>{html.escape(c.goal_it)}</i></p>")
                for tl in c.tools:
                    d = tl.docs
                    parts.append(f"<h3>{html.escape(tl.name)}</h3>"
                                 f"<p><b>Cosa fa:</b> {html.escape(d.get('what_it_does',''))}<br>"
                                 f"<b>Quando:</b> {html.escape(d.get('when',''))}<br>"
                                 f"<b>Permessi:</b> {html.escape(d.get('permissions',''))}</p>")
            browser.setHtml("".join(parts))
            lay.addWidget(browser, 1)

    # --------------------------------------------------- simple placeholder
    class CliBackedPage(QtWidgets.QWidget):
        def __init__(self, title, cmd_hint):
            super().__init__()
            lay = QtWidgets.QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.addWidget(h1(title))
            lay.addWidget(muted(
                f"In questa versione alpha la gestione di «{title}» è disponibile dalla riga di "
                f"comando con lo stesso motore della GUI:<br><code>{html.escape(cmd_hint)}</code>"))
            lay.addStretch(1)

    # ---------------------------------------------------------- main window
    class MainWindow(QtWidgets.QMainWindow):
        PAGES = [  # key, label, beginner-visible
            ("explore", "Esplora", True),
            ("dashboard", "Panoramica", True),
            ("catalog", "Strumenti", False),
            ("privacy", "Privacy", True),
            ("projects", "Progetti", False),
            ("reports", "Report", False),
            ("learn", "Impara", True),
        ]

        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"CyberDistro — Security Center {__version__}")
            self.resize(1180, 760)
            self.mode = Mode.parse(os.environ.get("CYBERDISTRO_MODE"), Mode.BEGINNER)
            self.catalog = Catalog.load()
            self.operations: list[tuple[str, int]] = []

            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            layout = QtWidgets.QHBoxLayout(central)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            # Sidebar
            side = QtWidgets.QWidget()
            side.setObjectName("Sidebar")
            side.setFixedWidth(220)
            side.setStyleSheet("#Sidebar { background: palette(alternate-base); border-right: 1px solid palette(midlight); }")
            sl = QtWidgets.QVBoxLayout(side)
            sl.setContentsMargins(10, 14, 10, 14)
            brand = QtWidgets.QLabel("<b style='font-size:16px'>CyberDistro</b><br>"
                                     "<span style='color:gray'>Security Center</span>")
            sl.addWidget(brand)
            sl.addSpacing(8)
            self.nav = QtWidgets.QListWidget()
            self.nav.setFrameShape(QtWidgets.QFrame.NoFrame)
            self.nav.setStyleSheet("QListWidget { background: transparent; font-size: 14px; }"
                                   "QListWidget::item { padding: 9px 12px; border-radius: 9px; }"
                                   "QListWidget::item:selected { background: palette(highlight); color: palette(highlighted-text); }")
            self.nav.setIconSize(QtCore.QSize(20, 20))
            self.nav.currentRowChanged.connect(self._nav_changed)
            sl.addWidget(self.nav, 1)
            sl.addWidget(QtWidgets.QLabel("Modalità"))
            self.mode_combo = QtWidgets.QComboBox()
            for m in Mode:
                self.mode_combo.addItem(MODE_LABELS[m], m)
            self.mode_combo.setCurrentIndex(list(Mode).index(self.mode))
            self.mode_combo.currentIndexChanged.connect(self._mode_changed)
            sl.addWidget(self.mode_combo)
            layout.addWidget(side)

            self.stack = QtWidgets.QStackedWidget()
            layout.addWidget(self.stack, 1)

            self.pages = {
                "explore": ExplorePage(self),
                "dashboard": DashboardPage(self),
                "catalog": CatalogPage(self),
                "privacy": PrivacyPage(self),
                "projects": CliBackedPage("Progetti", "cyberdistro-sc project new NOME --owner CHI --scope 192.168.1.0/24"),
                "reports": CliBackedPage("Report", "cyberdistro-sc report NOME --format html"),
                "learn": LearnPage(self),
            }
            for key, _, _ in self.PAGES:
                self.stack.addWidget(self.pages[key])
            self._rebuild_nav()
            self.go("explore" if self.mode is Mode.BEGINNER else "dashboard")

        # ---- navigation
        def _rebuild_nav(self):
            self.nav.blockSignals(True)
            self.nav.clear()
            icons = {"explore": "network-wireless", "dashboard": "dashboard-show",
                     "catalog": "applications-utilities", "privacy": "security-high",
                     "projects": "folder", "reports": "x-office-document", "learn": "help-contents"}
            for key, label, beginner_ok in self.PAGES:
                if self.mode is Mode.BEGINNER and not beginner_ok:
                    continue
                it = QtWidgets.QListWidgetItem(QtGui.QIcon.fromTheme(icons[key]), label)
                it.setData(QtCore.Qt.UserRole, key)
                self.nav.addItem(it)
            self.nav.blockSignals(False)

        def go(self, key: str):
            self.stack.setCurrentWidget(self.pages[key])
            for i in range(self.nav.count()):
                if self.nav.item(i).data(QtCore.Qt.UserRole) == key:
                    self.nav.blockSignals(True)
                    self.nav.setCurrentRow(i)
                    self.nav.blockSignals(False)
                    break

        def _nav_changed(self, row):
            if row < 0:
                return
            self.stack.setCurrentWidget(self.pages[self.nav.item(row).data(QtCore.Qt.UserRole)])

        def _mode_changed(self, idx):
            # Mode is a str-Enum: Qt would hand back a plain str from itemData,
            # so resolve by position to keep a real Mode member.
            self.mode = list(Mode)[idx]
            current = self.stack.currentWidget()
            self.pages["dashboard"].rebuild()
            self._rebuild_nav()
            key = next(k for k, p in self.pages.items() if p is current)
            if self.mode is Mode.BEGINNER and not dict((k, b) for k, _, b in self.PAGES)[key]:
                key = "explore"
            self.go(key)

        # ---- shared actions
        def log_operation(self, command: str, returncode: int):
            """Audit trail shown in the status bar (and recordable in a project)."""
            self.operations.append((command, returncode))
            if self.mode is not Mode.BEGINNER:
                self.statusBar().showMessage(f"Eseguito: {command}  (exit {returncode})", 15000)
            else:
                self.statusBar().showMessage("Operazione completata.", 5000)

        def verify_file(self):
            from ..tools import forensic_hash as fh
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Scegli il file da verificare")
            if not path:
                return
            try:
                res = fh.compute(path, ("sha256",))
                digest = res.hashes["sha256"]
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Verifica file", f"Errore: {e}")
                return
            QtWidgets.QMessageBox.information(
                self, "Impronta del file",
                f"<b>{html.escape(os.path.basename(path))}</b><br><br>"
                f"SHA‑256:<br><code>{digest}</code><br><br>"
                "Se l'impronta coincide con quella pubblicata da chi ti ha dato il file, "
                "il file non è stato modificato.")

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
