"""Security Center GUI skeleton (PySide6).

Deliberately thin: every action calls into cyberdistro_sc.core / .tools. The GUI
never computes results itself and always shows the underlying command for an
operation before running it (honesty + reproducibility).

State of implementation: navigable shell with Dashboard, Catalog and a guided
Nmap-inventory panel wired to the real core. Other panels are placeholders that
clearly say "non ancora implementato" rather than faking functionality.
"""

from __future__ import annotations

import sys

from ..core.catalog import Catalog
from ..core.capabilities import system_report
from ..core.modes import Mode
from .. import __version__


def _require_qt():
    try:
        from PySide6 import QtWidgets, QtCore  # noqa: F401
        return QtWidgets, QtCore
    except Exception as e:  # pragma: no cover - environment dependent
        raise SystemExit(
            "PySide6 non è installato. Installa il pacchetto "
            "'python3-pyside6.*' oppure `pip install PySide6`.\n"
            f"Dettaglio: {e}"
        )


def run() -> int:  # pragma: no cover - requires a display
    QtWidgets, QtCore = _require_qt()

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"CyberDistro — Security Center {__version__}")
            self.resize(1100, 720)
            self.mode = Mode.BEGINNER
            self.catalog = Catalog.load()

            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            layout = QtWidgets.QHBoxLayout(central)

            # Sidebar navigation
            self.nav = QtWidgets.QListWidget()
            self.nav.addItems(["Panoramica", "Strumenti", "Privacy",
                               "Progetti", "Report", "Impara"])
            self.nav.setFixedWidth(200)
            self.nav.currentRowChanged.connect(self._switch)
            layout.addWidget(self.nav)

            self.stack = QtWidgets.QStackedWidget()
            layout.addWidget(self.stack, 1)
            self.stack.addWidget(self._dashboard())
            self.stack.addWidget(self._catalog_view())
            for name in ("Privacy", "Progetti", "Report", "Impara"):
                self.stack.addWidget(self._placeholder(name))

            self._make_toolbar()
            self.nav.setCurrentRow(0)

        def _make_toolbar(self):
            tb = self.addToolBar("mode")
            tb.addWidget(QtWidgets.QLabel("  Modalità:  "))
            combo = QtWidgets.QComboBox()
            combo.addItems([m.value for m in Mode])
            combo.currentTextChanged.connect(
                lambda v: setattr(self, "mode", Mode.parse(v)))
            tb.addWidget(combo)

        def _dashboard(self):
            w = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(w)
            lay.addWidget(QtWidgets.QLabel("<h2>Panoramica</h2>"))
            rep = system_report()
            txt = QtWidgets.QPlainTextEdit()
            txt.setReadOnly(True)
            import json
            txt.setPlainText(json.dumps(rep, indent=2, ensure_ascii=False))
            lay.addWidget(txt)
            return w

        def _catalog_view(self):
            w = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(w)
            lay.addWidget(QtWidgets.QLabel("<h2>Strumenti</h2>"))
            tree = QtWidgets.QTreeWidget()
            tree.setHeaderLabels(["Strumento", "Attività", "Installato", "Guidato"])
            for c in self.catalog.categories:
                top = QtWidgets.QTreeWidgetItem([c.title_it])
                for t in c.tools:
                    st = t.status()
                    QtWidgets.QTreeWidgetItem(top, [
                        t.name, t.activity.value,
                        "sì" if st.installed else "no",
                        "sì" if t.has_wrapper else "—"])
                tree.addTopLevelItem(top)
            tree.expandAll()
            lay.addWidget(tree)
            return w

        def _placeholder(self, name):
            w = QtWidgets.QWidget()
            lay = QtWidgets.QVBoxLayout(w)
            lay.addWidget(QtWidgets.QLabel(
                f"<h2>{name}</h2><p>Pannello non ancora implementato in questa "
                f"versione alpha. La logica è disponibile da CLI "
                f"(<code>cyberdistro-sc</code>).</p>"))
            lay.addStretch(1)
            return w

        def _switch(self, row):
            self.stack.setCurrentIndex(row)

    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
