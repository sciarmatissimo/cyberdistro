"""GUI layer (PySide6). Presentation only — delegates all logic to core.

This is a navigable skeleton: dashboard, catalog browser, mode switch, and a
guided-run panel that previews the exact command before execution. It imports
PySide6 lazily so the package stays importable (and testable) on systems without
Qt. Run with: ``python3 -m cyberdistro_sc.gui`` on a system with PySide6.
"""
