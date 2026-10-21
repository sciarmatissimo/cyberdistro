"""Safe command execution.

Design rules:
  * Commands are built as an argv **list** and executed WITHOUT a shell
    (shell=False). No string interpolation into a shell → no shell injection.
  * Every execution produces a CommandResult that records the exact argv, so
    the operation is auditable and reproducible in every mode.
  * A dry-run produces a CommandPlan without executing anything — used by the
    GUI/CLI to show the user what *would* run before they confirm.
  * Timeouts are mandatory for active operations.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class CommandPlan:
    """A command that is ready to run but has not run yet."""

    tool_id: str
    argv: list[str]
    description: str = ""
    needs_privilege: bool = False
    activity: str = "passive"

    @property
    def shell_preview(self) -> str:
        """Human-readable, copy-pasteable reproduction of the command."""
        return " ".join(shlex.quote(a) for a in self.argv)


@dataclass
class CommandResult:
    tool_id: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: float
    duration_s: float
    timed_out: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def shell_preview(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "command": self.shell_preview,
            "argv": list(self.argv),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 3),
            "stdout_len": len(self.stdout),
            "stderr": self.stderr[-2000:],
        }


class CommandRunner:
    """Executes CommandPlans. Never uses a shell."""

    def __init__(self, default_timeout: float = 300.0):
        self.default_timeout = default_timeout

    @staticmethod
    def tool_available(executable: str) -> bool:
        return shutil.which(executable) is not None

    def run(self, plan: CommandPlan, timeout: float | None = None,
            input_text: str | None = None) -> CommandResult:
        exe = plan.argv[0]
        if shutil.which(exe) is None:
            # Return a structured "not installed" result rather than raising:
            # the UI must tell the user the component is missing, not crash.
            return CommandResult(
                tool_id=plan.tool_id, argv=list(plan.argv), returncode=127,
                stdout="", stderr=f"{exe}: not installed on this system",
                started_at=time.time(), duration_s=0.0,
                extra={"not_installed": True},
            )
        t = timeout if timeout is not None else self.default_timeout
        start = time.time()
        timed_out = False
        try:
            proc = subprocess.run(
                plan.argv,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=t,
                shell=False,          # never a shell
                check=False,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            timed_out = True
            rc = -1
            out = e.stdout or "" if isinstance(e.stdout, str) else ""
            err = (e.stderr or "" if isinstance(e.stderr, str) else "") + \
                  f"\n[timed out after {t}s]"
        dur = time.time() - start
        return CommandResult(
            tool_id=plan.tool_id, argv=list(plan.argv), returncode=rc,
            stdout=out, stderr=err, started_at=start, duration_s=dur,
            timed_out=timed_out,
        )
