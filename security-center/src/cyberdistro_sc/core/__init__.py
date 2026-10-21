"""Headless core of the Security Center (no GUI imports allowed here)."""

from .modes import Mode
from .authorization import Authorization, AuthorizationError, ActivityKind
from .runner import CommandRunner, CommandResult, CommandPlan
from .capabilities import detect_tool, system_report, ToolStatus

__all__ = [
    "Mode",
    "Authorization",
    "AuthorizationError",
    "ActivityKind",
    "CommandRunner",
    "CommandResult",
    "CommandPlan",
    "detect_tool",
    "system_report",
    "ToolStatus",
]
