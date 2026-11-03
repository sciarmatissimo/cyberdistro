"""Offscreen GUI smoke test: replays the synthetic-capture fixtures into a temporary
database, opens every section of the Security Center Sentinel and saves a
screenshot of each. Exits non-zero on any exception.

    QT_QPA_PLATFORM=offscreen PYTHONPATH=src python3 tests/gui_smoke.py OUTDIR
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).parent
out = Path(sys.argv[1] if len(sys.argv) > 1 else "gui-shots")
out.mkdir(parents=True, exist_ok=True)
tmp = Path(tempfile.mkdtemp())
os.environ.update(SENTINEL_STATE=str(tmp), SENTINEL_RUN=str(tmp), HOME=str(tmp),
                  SENTINEL_EVE=str(HERE / "fixtures/eve.json.gz"), SENTINEL_ZEEK=str(HERE / "fixtures/zeek"),
                  SENTINEL_SENSOR_LOG=str(HERE / "fixtures/sensor.jsonl"))

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from cyberdistro_sentinel.config import Paths, Thresholds  # noqa: E402
from cyberdistro_sentinel.daemon import replay  # noqa: E402
from cyberdistro_sentinel.gui.app import CSS, Main  # noqa: E402
from cyberdistro_sentinel.status import Health, decide  # noqa: E402
from cyberdistro_sentinel.store import Store  # noqa: E402

paths = Paths()
store = Store(paths.db)
corr = replay(paths, store, Thresholds())
incs = store.incidents()
now = max(i["last_ts"] for i in incs)
st = decide(incs, Health(True, True, True, True), now)
st["updated"] = time.time()                      # fresh, as if the daemon wrote it now
(tmp / "status.json").write_text(json.dumps({**st, "devices": len(corr.devices)}))

QMessageBox.information = staticmethod(lambda *a, **k: None)  # no modal dialogs offscreen
app = QApplication(sys.argv[:1])
app.setStyleSheet(CSS)
w = Main(paths, smoke=True)
w.resize(1366, 768)
w.show()
app.processEvents()
shots = []
for i, name in enumerate(["Home", "Rete", "Protezione", "Assistente AI", "Report", "Privacy", "Impostazioni"]):
    w.go(name)
    if name == "Rete" and w.data.devices:
        w.show_device(next(d for d in w.data.devices if d.get("ip") == "192.168.1.57") if any(
            d.get("ip") == "192.168.1.57" for d in w.data.devices) else w.data.devices[0])
    if name == "Protezione":
        w.inc_list.setCurrentRow(0)
    if name == "Assistente AI":
        for q in ("La mia rete è sicura?", "Qualcuno sta cercando di attaccare la mia rete?", "Cosa devo fare adesso?"):
            w.ask(q)
    if name == "Report":
        w.make_report()
    for _ in range(5):
        app.processEvents()
    p = out / f"{i + 1:02d}-{name.split()[0].lower()}.png"
    w.grab().save(str(p))
    shots.append(p.name)
w.set_advanced(True)
w.go("Protezione")
w.inc_list.setCurrentRow(0)
app.processEvents()
w.grab().save(str(out / "08-protezione-avanzata.png"))
assert st["colour"] == "rosso", st
assert w.dot.colour == "rosso"
assert w.last_report and w.last_report.exists()
print("GUI smoke OK:", ", ".join(shots), "| status", st["colour"], "| incidents", len(incs),
      "| devices", len(w.data.devices))
w.close()
