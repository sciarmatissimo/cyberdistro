"""Guided wrappers around real tools.

Each wrapper:
  * builds an argv list (never a shell string),
  * enforces authorization for active operations,
  * parses the tool's real output into a structured result,
  * can produce a CommandPlan for dry-run/preview so the user sees the exact
    command before confirming.
Wrappers never fabricate output and never hide that a tool is missing.
"""
