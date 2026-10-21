"""Forensic hashing with chain-of-custody semantics.

Computes cryptographic hashes of files/images to prove integrity, and verifies
a file against a previously recorded hash. Streams in chunks (handles large
disk images without loading them into RAM). Pure-Python → fully testable here.

This wrapper works on WORKING COPIES and never modifies the input. It does not
and cannot make a medium hardware write-protected; if write-blocking matters,
use a hardware write-blocker and the wrapper will record that it was declared,
not assert a guarantee the OS cannot make.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field

ALGORITHMS = ("sha256", "sha1", "md5")
_CHUNK = 1024 * 1024


@dataclass
class HashRecord:
    path: str
    size_bytes: int
    hashes: dict[str, str]
    computed_at: float = field(default_factory=time.time)
    write_blocker_declared: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "hashes": dict(self.hashes),
            "computed_at": self.computed_at,
            "write_blocker_declared": self.write_blocker_declared,
            "note": (
                "write_blocker_declared reflects an operator statement, not an "
                "OS-enforced guarantee of write protection."
            ),
        }


def explain() -> dict:
    return {
        "what_it_does": "Calcola e verifica hash crittografici per dimostrare "
                        "che un'evidenza non è stata alterata.",
        "when": "All'inizio di un'indagine (per fissare lo stato) e dopo ogni "
                "trasferimento (per dimostrare l'integrità).",
        "permissions": "Nessun privilegio speciale. Lavora su copie.",
        "algorithms": list(ALGORITHMS),
    }


def compute(path: str, algorithms: tuple[str, ...] = ("sha256",),
            write_blocker_declared: bool = False) -> HashRecord:
    for a in algorithms:
        if a not in ALGORITHMS:
            raise ValueError(f"unsupported algorithm {a!r}")
    hs = {a: hashlib.new(a) for a in algorithms}
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            for h in hs.values():
                h.update(chunk)
    return HashRecord(
        path=os.path.abspath(path), size_bytes=size,
        hashes={a: h.hexdigest() for a, h in hs.items()},
        write_blocker_declared=write_blocker_declared,
    )


def verify(path: str, expected: str, algorithm: str = "sha256") -> bool:
    """Return True iff the file's current hash equals ``expected``."""
    rec = compute(path, (algorithm,))
    return rec.hashes[algorithm].lower() == expected.strip().lower()
