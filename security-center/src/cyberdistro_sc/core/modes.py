"""Usage modes.

A mode is an *exposure level*, not a different engine. Switching modes changes
which parameters and explanations are shown and which defaults are pre-selected.
It never silently changes results or drops a configuration the user already set:
the runner always records the exact command that ran, in every mode.
"""

from __future__ import annotations

from enum import Enum


class Mode(str, Enum):
    BEGINNER = "beginner"
    PROFESSIONAL = "professional"
    EXPERT = "expert"

    @property
    def shows_raw_command(self) -> bool:
        """Expert always shows and lets you reproduce the underlying command.

        Professional shows it on request; Beginner hides it by default but it is
        still recorded in the project log (never hidden from the audit trail).
        """
        return self is Mode.EXPERT

    @property
    def exposes_advanced_params(self) -> bool:
        return self in (Mode.PROFESSIONAL, Mode.EXPERT)

    @property
    def allows_terminal(self) -> bool:
        return self is Mode.EXPERT

    @classmethod
    def parse(cls, value: str | None, default: "Mode" = None) -> "Mode":
        if value is None:
            return default or cls.BEGINNER
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(
                f"unknown mode {value!r}; expected one of "
                f"{', '.join(m.value for m in cls)}"
            )
