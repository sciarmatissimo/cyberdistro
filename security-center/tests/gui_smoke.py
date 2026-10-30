"""Offscreen GUI smoke test (not part of unittest discovery: needs PySide6).

Builds the whole Security Center UI with QT_QPA_PLATFORM=offscreen, visits
every page in every mode, runs a real local-network scan through the GUI code
path (if nmap is present), opens the device-details dialog, and writes PNG
screenshots to the directory given as argv[1].

    QT_QPA_PLATFORM=offscreen PYTHONPATH=src python3 tests/gui_smoke.py /tmp/shots
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
out_dir = sys.argv[1] if len(sys.argv) > 1 else "gui-shots"
os.makedirs(out_dir, exist_ok=True)

from PySide6 import QtCore, QtGui, QtWidgets  # noqa: E402

# Optional: render with a real icon theme (e.g. Papirus, as shipped in the ISO)
# to check that the device icon names resolve: CYBERDISTRO_SMOKE_ICON_THEME=Papirus
if os.environ.get("CYBERDISTRO_SMOKE_ICON_THEME"):
    # The offscreen platform has no platform theme, so point Qt at the
    # standard icon directories explicitly (Plasma does this for real sessions).
    QtGui.QIcon.setThemeSearchPaths(["/usr/share/icons", os.path.expanduser("~/.local/share/icons")])
    QtGui.QIcon.setThemeName(os.environ["CYBERDISTRO_SMOKE_ICON_THEME"])

from cyberdistro_sc.gui.app import build_app  # noqa: E402
from cyberdistro_sc.core.modes import Mode  # noqa: E402

# In CI (or any network we do not own) never sweep the real subnet: inject a
# deterministic fake scan so the GUI code path is still exercised end-to-end.
if os.environ.get("CYBERDISTRO_SMOKE_NO_SCAN") == "1":
    import subprocess
    from cyberdistro_sc.tools import explore as ex

    def _fake_scan(net, auth, **kw):
        auth.require(net.cidr, ex.ActivityKind.ACTIVE_LIGHT)   # gating still real
        plan = ex.plan_network_scan(net.cidr)
        devs = [
            ex.Device(address=net.address, kind="self", source="network",
                      details={"rete": net.cidr, "interfaccia": net.interface}),
            ex.Device(address=net.gateway or "192.0.2.1", kind="router", name="fritz.box",
                      mac="A4:2B:B0:11:22:33", vendor="AVM GmbH", source="network",
                      details={"rete": net.cidr, "interfaccia": net.interface}),
            ex.Device(address="192.0.2.23", kind="phone", name="Giovannis-iPhone",
                      mac="3C:22:FB:AA:BB:CC", vendor="Apple, Inc.", source="network",
                      details={"rete": net.cidr, "interfaccia": net.interface}),
            ex.Device(address="192.0.2.77", kind="printer", name="HP-LaserJet-M15",
                      source="network", details={"rete": net.cidr}),
        ]
        return plan, subprocess.CompletedProcess(plan.argv, 0, "", ""), devs

    from cyberdistro_sc.gui import app as _gui_mod
    _gui_mod.ex.scan_network = _fake_scan
    if not ex.local_networks():
        ex.local_networks = lambda run=None: [ex.LocalNetwork(
            interface="wlan0", kind="wifi", address="192.0.2.2", cidr="192.0.2.0/24",
            gateway="192.0.2.1", ssid="CasaMia")]
    print("[smoke] real network scan disabled (CYBERDISTRO_SMOKE_NO_SCAN=1); using fake devices")

app, win = build_app(["smoke"])
win.show()
app.processEvents()


def shot(name):
    app.processEvents()
    pm = win.grab()
    path = os.path.join(out_dir, f"{name}.png")
    assert pm.save(path), f"could not save {path}"
    print(f"[shot] {path} ({pm.width()}x{pm.height()})")


def wait(ms):
    loop = QtCore.QEventLoop()
    QtCore.QTimer.singleShot(ms, loop.quit)
    loop.exec()


errors = []

# 1) Beginner mode: nav must contain Esplora first and hide pro-only pages.
assert win.mode is Mode.BEGINNER
labels = [win.nav.item(i).text() for i in range(win.nav.count())]
print("[nav beginner]", labels)
assert labels[0] == "Esplora", labels
assert "Strumenti" not in labels and "Progetti" not in labels

win.go("dashboard"); shot("01-beginner-panoramica")
win.go("explore"); shot("02-beginner-esplora-vuoto")

# 2) Real network scan through the GUI path (auto-confirm the dialog).
explore = win.pages["explore"]
if explore.networks:
    net = explore.net_combo.currentData()
    explore._confirmed.add(net.cidr)          # simulate the user's confirmation
    explore.scan_network()
    for _ in range(600):                        # up to 60 s
        wait(100)
        if explore._worker is None:
            break
    print("[explore] status:", explore.net_status.text())
    print("[explore] devices:", [(d.address, d.kind) for d in explore.net_devices])
    shot("03-beginner-esplora-risultati")
    assert explore.net_grid.count() == len(explore.net_devices)
    if explore.net_devices:
        # Open the details dialog for the first tile without blocking.
        from cyberdistro_sc.gui import app as gui_app  # noqa: F401
        item = explore.net_grid.item(0)
        dev = item.data(QtCore.Qt.UserRole)
        # Access the dialog class through the closure: re-create via itemClicked path.
        dlg_holder = {}

        def _grab_dialog():
            for w in app.topLevelWidgets():
                if isinstance(w, QtWidgets.QDialog) and w.isVisible():
                    dlg_holder["dlg"] = w
                    pm = w.grab()
                    pm.save(os.path.join(out_dir, "04-dettagli-dispositivo.png"))
                    print("[shot]", os.path.join(out_dir, "04-dettagli-dispositivo.png"))
                    w.accept()
        QtCore.QTimer.singleShot(300, _grab_dialog)
        explore.net_grid.itemClicked.emit(item)
        wait(600)
        assert "dlg" in dlg_holder, "device details dialog did not open"
else:
    print("[explore] no local network in this environment — scan skipped")

# 3) Bluetooth tab (will report unavailable here; must not crash).
explore.tabs.setCurrentIndex(1); shot("05-beginner-bluetooth")
print("[bluetooth] status:", explore.bt_status.text())
explore.tabs.setCurrentIndex(0)

# 4) Privacy + Impara pages.
win.go("privacy"); shot("06-privacy")
win.go("learn"); shot("07-impara")

# 5) Switch to Professional: full nav, dashboard changes, then back (reversible).
win.mode_combo.setCurrentIndex(list(Mode).index(Mode.PROFESSIONAL))
labels = [win.nav.item(i).text() for i in range(win.nav.count())]
print("[nav professional]", labels)
assert "Strumenti" in labels and "Progetti" in labels and "Esplora" in labels
win.go("dashboard"); shot("08-pro-panoramica")
win.go("catalog"); shot("09-pro-strumenti")
win.go("explore"); shot("10-pro-esplora")
win.mode_combo.setCurrentIndex(list(Mode).index(Mode.BEGINNER))
labels = [win.nav.item(i).text() for i in range(win.nav.count())]
assert "Strumenti" not in labels
# device list survived the mode round-trip (mode never drops results)
assert explore.net_grid.count() == len(explore.net_devices)

if os.environ.get("CYBERDISTRO_SMOKE_ICON_THEME"):
    from cyberdistro_sc.tools import explore as _ex
    missing = [k for k in _ex.KINDS if not any(QtGui.QIcon.hasThemeIcon(n) for n in _ex.icon_candidates(k))]
    print("[icons] theme:", QtGui.QIcon.themeName(), "kinds without a theme icon:", missing or "none")

print("GUI SMOKE: OK")
