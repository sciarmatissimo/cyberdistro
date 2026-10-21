"""Project & evidence management.

A project holds the declared authorization (owner + scope), a chronological log
of every operation (with the exact command and a content hash of any output
saved), and the findings. Everything is stored as JSON so it is inspectable and
portable. Projects live under a base directory that, on the live system, should
point at encrypted persistence when available.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict

from .authorization import Authorization


def _slug(name: str) -> str:
    keep = "-_. "
    s = "".join(c if (c.isalnum() or c in keep) else "_" for c in name).strip()
    return s.replace(" ", "_") or "project"


@dataclass
class Finding:
    title: str
    severity: str = "info"          # info|low|medium|high|critical
    confidence: str = "confirmed"   # confirmed|likely|possible|false_positive
    source: str = "tool"            # tool|ai|analyst
    detail: str = ""
    evidence_ref: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LogEntry:
    timestamp: float
    tool_id: str
    command: str
    returncode: int
    note: str = ""
    output_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Project:
    SEVERITIES = ("info", "low", "medium", "high", "critical")
    CONFIDENCES = ("confirmed", "likely", "possible", "false_positive")

    def __init__(self, base_dir: str, auth: Authorization):
        self.base_dir = base_dir
        self.auth = auth
        self.dir = os.path.join(base_dir, _slug(auth.project))
        self.log: list[LogEntry] = []
        self.findings: list[Finding] = []
        self.created_at = time.time()

    # ---- persistence --------------------------------------------------
    @property
    def _meta_path(self) -> str:
        return os.path.join(self.dir, "project.json")

    def save(self) -> str:
        os.makedirs(os.path.join(self.dir, "evidence"), exist_ok=True)
        data = {
            "authorization": self.auth.to_dict(),
            "created_at": self.created_at,
            "log": [e.to_dict() for e in self.log],
            "findings": [f.to_dict() for f in self.findings],
        }
        tmp = self._meta_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, self._meta_path)
        return self._meta_path

    @classmethod
    def load(cls, base_dir: str, name: str) -> "Project":
        d = os.path.join(base_dir, _slug(name))
        with open(os.path.join(d, "project.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        proj = cls(base_dir, Authorization.from_dict(data["authorization"]))
        proj.created_at = data.get("created_at", time.time())
        proj.log = [LogEntry(**e) for e in data.get("log", [])]
        proj.findings = [Finding(**f) for f in data.get("findings", [])]
        return proj

    # ---- recording ----------------------------------------------------
    def save_evidence(self, name: str, content: bytes) -> tuple[str, str]:
        """Write evidence to the project and return (path, sha256).

        Evidence is written as a working copy; the hash is recorded so the file
        can later be verified unchanged (chain of custody).
        """
        os.makedirs(os.path.join(self.dir, "evidence"), exist_ok=True)
        path = os.path.join(self.dir, "evidence", _slug(name))
        with open(path, "wb") as fh:
            fh.write(content)
        digest = hashlib.sha256(content).hexdigest()
        return path, digest

    def record(self, tool_id: str, command: str, returncode: int,
               note: str = "", output_sha256: str = "") -> None:
        self.log.append(LogEntry(
            timestamp=time.time(), tool_id=tool_id, command=command,
            returncode=returncode, note=note, output_sha256=output_sha256,
        ))

    def add_finding(self, finding: Finding) -> None:
        if finding.severity not in self.SEVERITIES:
            raise ValueError(f"bad severity {finding.severity!r}")
        if finding.confidence not in self.CONFIDENCES:
            raise ValueError(f"bad confidence {finding.confidence!r}")
        self.findings.append(finding)
