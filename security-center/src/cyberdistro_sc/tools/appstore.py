"""On-demand application catalog ("app store") for the Security Center.

These applications are not shipped in the ISO: the user installs the ones they
need from the Forense / Reversing sections. This module is the single source of
truth (loaded from data/ondemand.yaml) and builds the *exact argv* used to
install or launch each app — always as a list, never a shell string, so there
is no shell injection and every action is auditable/reproducible.

Install goes through the privileged helper /usr/local/sbin/cyberdistro-install-app
(invoked via pkexec). Detection of "already installed" is done at runtime by
looking for the app's binary on PATH — the catalog never *claims* something is
installed; it checks.
"""

from __future__ import annotations

import importlib.resources as res
import shutil
import subprocess
from dataclasses import dataclass, field

import yaml

INSTALL_HELPER = "/usr/local/sbin/cyberdistro-install-app"
VALID_SOURCES = ("debian", "kali", "pip")
VALID_LAUNCH = ("gui", "gui-root", "web", "terminal")


@dataclass
class App:
    id: str
    section: str
    name: str
    package: str                 # space-separated apt/pip package(s)
    source: str                  # debian | kali | pip
    binary: str                  # executable used to detect install + launch
    gui: bool
    launch: str                  # gui | gui-root | web | terminal
    desc_it: str = ""
    use_it: str = ""
    note_it: str = ""
    check_import: str = ""       # if set, "installed" means this module imports

    # ---- validation -------------------------------------------------
    def validate(self) -> None:
        if self.source not in VALID_SOURCES:
            raise ValueError(f"{self.id}: source non valido {self.source!r}")
        if self.launch not in VALID_LAUNCH:
            raise ValueError(f"{self.id}: launch non valido {self.launch!r}")
        if not self.package.strip():
            raise ValueError(f"{self.id}: package mancante")
        if not self.binary.strip():
            raise ValueError(f"{self.id}: binary mancante")

    @property
    def packages(self) -> list[str]:
        return self.package.split()

    # ---- runtime status ---------------------------------------------
    def installed(self) -> bool:
        if self.check_import:
            import importlib.util
            try:
                return importlib.util.find_spec(self.check_import) is not None
            except (ImportError, ValueError):
                return False
        return shutil.which(self.binary) is not None

    # ---- command construction (argv lists; no shell) ----------------
    def install_argv(self, *, privileged: bool = True) -> list[str]:
        """argv to install this app. Prefixed with pkexec unless already root."""
        flag = {"debian": "--apt", "kali": "--kali", "pip": "--pip"}[self.source]
        argv = [INSTALL_HELPER, flag, *self.packages]
        if privileged:
            argv = ["pkexec", *argv]
        return argv

    def launch_argv(self) -> list[str]:
        """argv to start the app once installed.

        GUI apps run directly; root GUI apps go through pkexec; web and terminal
        tools open in Konsole so the user sees output / the printed URL.
        """
        term = shutil.which("konsole") or "konsole"
        if self.launch == "gui":
            return [self.binary]
        if self.launch == "gui-root":
            return ["pkexec", self.binary]
        if self.launch == "web":
            # Tool prints a local URL; keep the terminal open to read it.
            return [term, "--hold", "-e", self.binary]
        # terminal: land in an interactive shell with a ready hint
        hint = self._terminal_hint()
        return [term, "-e", "bash", "-lc", hint]

    def _terminal_hint(self) -> str:
        """A friendly interactive shell: show a one-line hint, then a shell.

        Built from the app id only (no user input), so it is a safe constant.
        """
        hints = {
            "testdisk": "echo '➜  Avvia il recupero guidato con:  sudo photorec'",
            "ewf-tools": "echo '➜  Acquisisci in formato E01 con:  sudo ewfacquire /dev/sdX'",
            "imaging-cli": "echo '➜  Copia un disco con hash:  sudo dc3dd if=/dev/sdX of=img.dd hash=sha256'",
            "carving": "echo '➜  Recupera file con:  foremost -t jpg,pdf -i immagine.dd -o recuperati/'",
            "plaso": "echo '➜  Crea la timeline con:  log2timeline.py caso.plaso immagine.dd'",
            "volatility3": "echo '➜  Analizza la RAM con:  vol -f memoria.raw windows.pslist'",
            "exiftool": "echo '➜  Leggi i metadati con:  exiftool file'",
            "hashdeep": "echo '➜  Verifica integrità con:  hashdeep -r -c sha256 cartella/'",
            "gdb": "echo '➜  Debug di un programma con:  gdb ./binario   (multiarch: gdb-multiarch)'",
            "tracers": "echo '➜  Osserva un programma con:  strace ./binario   oppure  ltrace ./binario'",
            "radare2": "echo '➜  Apri un binario con:  r2 ./binario   (poi:  aaa; afl; pdf @ main)'",
            "binwalk": "echo '➜  Estrai un firmware con:  binwalk -e firmware.bin'",
            "analysis-libs": "echo '➜  Sessione Python pronta (capstone, unicorn importabili)'; exec python3",
        }
        h = hints.get(self.id, f"echo 'Pronto: {self.binary}'")
        # Each branch ends in an interactive shell unless it already exec'd one.
        if "exec " in h:
            return h
        return h + "; exec bash"


@dataclass
class Section:
    id: str
    title_it: str
    icon: str
    intro_it: str
    apps: list[App] = field(default_factory=list)


class AppStore:
    def __init__(self, sections: list[Section]):
        self.sections = sections
        self._by_id = {a.id: a for s in sections for a in s.apps}

    @classmethod
    def load(cls, path: str | None = None) -> "AppStore":
        if path:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        else:
            text = res.files("cyberdistro_sc.data").joinpath(
                "ondemand.yaml").read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        sections = []
        for s in data.get("sections", []):
            apps = []
            for a in s.get("apps", []):
                app = App(
                    id=a["id"], section=s["id"], name=a["name"],
                    package=a["package"], source=a["source"], binary=a["binary"],
                    gui=bool(a.get("gui", False)), launch=a["launch"],
                    desc_it=a.get("desc_it", ""), use_it=a.get("use_it", ""),
                    note_it=a.get("note_it", ""), check_import=a.get("check_import", ""),
                )
                app.validate()
                apps.append(app)
            # GUI-first ordering within a section (beginner-friendly on top).
            apps.sort(key=lambda x: (not x.gui,))
            sections.append(Section(
                id=s["id"], title_it=s["title_it"], icon=s.get("icon", "applications-other"),
                intro_it=s.get("intro_it", "").strip(), apps=apps,
            ))
        return cls(sections)

    def section(self, section_id: str) -> Section | None:
        for s in self.sections:
            if s.id == section_id:
                return s
        return None

    def get(self, app_id: str) -> App | None:
        return self._by_id.get(app_id)

    def all_apps(self) -> list[App]:
        return [a for s in self.sections for a in s.apps]


# --------------------------------------------------------------------------
# Execution helpers (thin, injectable → unit-testable and stubbable in the GUI
# smoke test). Installation is privileged and auditable; launching is not.
def run_install(app: "App", runner=subprocess.run):
    """Install the app. Returns the completed process (returncode, stdout...)."""
    return runner(app.install_argv(), capture_output=True, text=True)


def run_launch(app: "App", spawner=subprocess.Popen):
    """Start the app (fire and forget)."""
    return spawner(app.launch_argv())
