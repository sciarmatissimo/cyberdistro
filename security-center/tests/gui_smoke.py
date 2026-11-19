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

# 1) Beginner mode: nav starts with Explore and hides pro-only pages.
#    Assert on page KEYS (UserRole), not labels, so the test is language-neutral.
assert win.mode is Mode.BEGINNER


def nav_keys():
    return [win.nav.item(i).data(QtCore.Qt.UserRole) for i in range(win.nav.count())]


keys = nav_keys()
print("[nav beginner]", keys)
assert keys[0] == "explore", keys
assert "catalog" not in keys and "projects" not in keys  # pro-only hidden
assert "monitor" in keys  # the new guided page is beginner-visible

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

# 3b) On-demand app sections. Stub install/launch so no real apt/pkexec runs,
#     but exercise the whole GUI path (worker thread, state flip install→open).
from cyberdistro_sc.tools import appstore as _A  # noqa: E402

_fake_installed = set()
_A.App.installed = lambda self: self.id in _fake_installed


class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


def _fake_install(app, runner=None):
    _fake_installed.add(app.id)
    return _FakeProc()


_launched = []
_A.run_install = _fake_install
_A.run_launch = lambda app, spawner=None: _launched.append(app.id)

forx = win.pages["forensics"]
# every forensic app is listed, GUI tools first
print("[forensics] apps:", [c.app.id for c in forx.cards])
assert forx.cards and forx.cards[0].app.gui
win.go("forensics"); shot("11-beginner-forense")

# click "Install and use" on the first card, wait for the worker, verify it
# flips to installed and launches.
card0 = forx.cards[0]
assert not card0.app.installed()
card0._on_click()
for _ in range(50):
    wait(50)
    if card0._worker is None:
        break
print("[forensics] after install:", card0.app.id, "->", card0.btn.text(),
      "launched:", _launched)
assert card0.app.id in _fake_installed and card0.app.id in _launched
assert card0.app.installed()
shot("12-beginner-forense-installato")

revx = win.pages["reversing"]
print("[reversing] apps:", [c.app.id for c in revx.cards])
assert any(c.app.id == "ghidra" for c in revx.cards)
win.go("reversing"); shot("13-beginner-reversing")

# 3c) Network monitor wizard. Stub the privileged bridge + capture so nothing
#     real runs, and feed fake tshark rows to populate the visual view.
from cyberdistro_sc.tools import netmonitor as _NM  # noqa: E402

_NM.list_interfaces = lambda run=None: [
    _NM.Interface(name="eth0", mac="aa:bb:cc:00:00:01", kind="wired", carrier=True,
                  addresses=["192.168.1.5/24"], is_default_route=True),
    _NM.Interface(name="eth1", mac="aa:bb:cc:00:00:02", kind="wired", carrier=True),
]


class _BridgeProc:
    returncode = 0
    stdout = "Bridge br0: attivo\n"
    stderr = ""


_NM.run_bridge = lambda argv, runner=None: _BridgeProc()
_NM.run_capture = lambda argv, spawner=None: None
_NM.wireshark_available = lambda: True
_NM.tshark_available = lambda: False  # skip QProcess in the headless test

mon = win.pages["monitor"]
win.go("monitor"); shot("14-monitor-step1-autorizzazione")
mon.chk_auth.setChecked(True)
mon._goto(1)                              # interfaces
assert len(mon.ifaces) == 2, mon.ifaces
shot("15-monitor-step2-schede")
mon._goto(2)                              # bridge step
mon.create_bridge_confirmed = True
# create_bridge pops a confirm dialog; drive it directly via the worker path
import cyberdistro_sc.tools.netmonitor as _nm2  # noqa
mon._worker = None
# bypass the modal by calling the worker body directly
proc = _NM.run_bridge(_NM.plan_bridge_create("eth0", "eth1"))
mon._bridge_done(proc)
assert mon._bridge_up
shot("16-monitor-step3-bridge")
# now on the monitor step: feed fake traffic and refresh the visual view
SAMPLE = "\n".join([
    "aa:bb:cc:00:00:11\t192.168.1.23\t8.8.8.8\texample.com\t\t",
    "aa:bb:cc:00:00:11\t192.168.1.23\t93.184.216.34\t\texample.com\t",
    "aa:bb:cc:00:00:22\t192.168.1.50\t1.1.1.1\t\tcdn.shop.net\t",
    "aa:bb:cc:00:00:22\t192.168.1.50\t1.1.1.1\t\t\tnews.example.org",
])
mon._feed_summary_text(SAMPLE)
mon._refresh_visual()
print("[monitor] devices:", mon.dev_grid.count(), "sites:", mon.site_list.count())
assert mon.dev_grid.count() == 2 and mon.site_list.count() >= 3
shot("17-monitor-step4-traffico")
mon.teardown()
assert not mon._bridge_up

# 4) Privacy + Learn pages.
win.go("privacy"); shot("06-privacy")
win.go("learn"); shot("07-impara")

# 5) Switch to Professional: full nav (incl. pro-only), then back (reversible).
win.mode_combo.setCurrentIndex(list(Mode).index(Mode.PROFESSIONAL))
pkeys = nav_keys()
print("[nav professional]", pkeys)
assert "catalog" in pkeys and "projects" in pkeys and "explore" in pkeys
win.go("dashboard"); shot("08-pro-panoramica")
win.go("catalog"); shot("09-pro-strumenti")
win.go("explore"); shot("10-pro-esplora")
win.mode_combo.setCurrentIndex(list(Mode).index(Mode.BEGINNER))
assert "catalog" not in nav_keys()
# device list survived the mode round-trip (mode never drops results)
assert explore.net_grid.count() == len(explore.net_devices)

if os.environ.get("CYBERDISTRO_SMOKE_ICON_THEME"):
    from cyberdistro_sc.tools import explore as _ex
    missing = [k for k in _ex.KINDS if not any(QtGui.QIcon.hasThemeIcon(n) for n in _ex.icon_candidates(k))]
    print("[icons] theme:", QtGui.QIcon.themeName(), "kinds without a theme icon:", missing or "none")

print("GUI SMOKE: OK")
