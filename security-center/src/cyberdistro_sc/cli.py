"""Command-line front-end for the Security Center core.

Fully usable without a GUI. Mirrors what the GUI offers: inspect the system,
browse the catalog, explain a tool, manage projects (with declared owner +
authorized scope), run guided operations, and export reports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .core.authorization import Authorization, AuthorizationError
from .core.capabilities import system_report
from .core.catalog import Catalog
from .core.modes import Mode
from .core.project import Project, Finding
from .core.runner import CommandRunner
from .core import report as report_mod

DEFAULT_BASE = os.environ.get(
    "CYBERDISTRO_PROJECTS",
    os.path.expanduser("~/.local/share/cyberdistro/projects"),
)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def cmd_doctor(args) -> int:
    rep = system_report()
    cat = Catalog.load()
    tools = []
    for t in cat.all_tools():
        st = t.status()
        tools.append({"id": t.id, "installed": st.installed,
                      "version": st.version})
    _print({"version": __version__, "system": rep, "tools": tools})
    return 0


def cmd_catalog(args) -> int:
    cat = Catalog.load()
    out = []
    for c in cat.categories:
        out.append({
            "category": c.id, "title": c.title_it, "goal": c.goal_it,
            "tools": [
                {"id": t.id, "name": t.name, "activity": t.activity.value,
                 "installed": t.status().installed,
                 "guided": t.has_wrapper}
                for t in c.tools
            ],
        })
    _print(out)
    return 0


def cmd_explain(args) -> int:
    cat = Catalog.load()
    tool = cat.get(args.tool_id)
    info = {"id": tool.id, "name": tool.name, "category": tool.category_id,
            "activity": tool.activity.value,
            "needs_privilege": tool.needs_privilege,
            "installed": tool.status().installed,
            "guided_wrapper": tool.has_wrapper, **tool.docs}
    if tool.has_wrapper:
        mod = tool.load_wrapper()
        if hasattr(mod, "explain"):
            info["wrapper_detail"] = mod.explain()
    _print(info)
    return 0


def cmd_project_new(args) -> int:
    auth = Authorization(project=args.name, owner=args.owner,
                         scope=list(args.scope or []), note=args.note or "")
    proj = Project(args.base, auth)
    proj.save()
    _print({"created": proj.dir, "authorization": auth.to_dict()})
    return 0


def cmd_run(args) -> int:
    cat = Catalog.load()
    tool = cat.get(args.tool_id)
    if not tool.has_wrapper:
        print(f"'{tool.id}' non ha un wrapper guidato; va lanciato nella sua "
              f"forma originale ({tool.executable}).", file=sys.stderr)
        return 2
    try:
        proj = Project.load(args.base, args.project)
    except FileNotFoundError:
        print(f"progetto '{args.project}' non trovato; crealo con "
              f"`project new`.", file=sys.stderr)
        return 2

    mode = Mode.parse(args.mode, Mode.BEGINNER)
    mod = tool.load_wrapper()

    if tool.id == "nmap-inventory":
        # Show the plan first (always), then run (unless --dry-run).
        p = mod.plan(args.target, profile=args.profile,
                     extra_args=args.extra or None)
        print(f"[comando] {p.shell_preview}", file=sys.stderr)
        if args.dry_run:
            _print({"dry_run": True, "command": p.shell_preview,
                    "activity": p.activity})
            return 0
        if p.activity == "active_intrusive" and not args.yes:
            print("Operazione invasiva: ripeti con --yes per confermare.",
                  file=sys.stderr)
            return 3
        try:
            result, hosts = mod.run(args.target, proj.auth,
                                    profile=args.profile,
                                    runner=CommandRunner(),
                                    extra_args=args.extra or None)
        except AuthorizationError as e:
            print(f"BLOCCATO (safe-by-default): {e}", file=sys.stderr)
            return 4
        proj.record(tool.id, result.shell_preview, result.returncode,
                    note=f"profile={args.profile}")
        for h in hosts:
            if h.state == "up":
                proj.add_finding(Finding(
                    title=f"Host attivo {h.address}"
                          + (f" ({h.hostname})" if h.hostname else ""),
                    severity="info", confidence="confirmed", source="tool",
                    detail=", ".join(
                        f"{s.port}/{s.protocol} {s.service}".strip()
                        for s in h.services if s.state == "open") or "nessuna porta aperta rilevata",
                ))
        proj.save()
        out = {"command": result.shell_preview, "returncode": result.returncode,
               "timed_out": result.timed_out,
               "installed": not result.extra.get("not_installed", False),
               "hosts": [h.to_dict() for h in hosts]}
        if result.extra.get("not_installed"):
            out["note"] = "nmap non è installato su questo sistema."
        _print(out)
        return 0 if result.ok else 1

    print(f"wrapper per '{tool.id}' non ancora esposto nella CLI.",
          file=sys.stderr)
    return 2


def cmd_explore(args) -> int:
    """Beginner discovery: local network devices or nearby Bluetooth devices."""
    from .tools import explore as ex
    if args.what == "networks":
        _print([n.to_dict() for n in ex.local_networks()])
        return 0
    if args.what == "network":
        nets = ex.local_networks()
        if not nets:
            print("Nessuna rete locale attiva (IPv4) trovata.", file=sys.stderr)
            return 2
        net = nets[0]
        if args.interface:
            match = [n for n in nets if n.interface == args.interface]
            if not match:
                print(f"interfaccia {args.interface!r} non trovata tra: "
                      f"{', '.join(n.interface for n in nets)}", file=sys.stderr)
                return 2
            net = match[0]
        plan = ex.plan_network_scan(net.cidr)
        print(f"[rete] {net.title} → {net.cidr}"
              + (" (ridotta a /24)" if net.capped else ""), file=sys.stderr)
        print(f"[comando] {plan.shell_preview}", file=sys.stderr)
        if not args.yes:
            print("Conferma che questa è la tua rete (o che sei autorizzato a "
                  "osservarla) ripetendo il comando con --yes.", file=sys.stderr)
            return 3
        auth = ex.local_authorization(net, owner=os.environ.get("USER", "utente"),
                                      confirmed=True)
        try:
            plan, proc, devices = ex.scan_network(net, auth)
        except AuthorizationError as e:
            print(f"BLOCCATO (safe-by-default): {e}", file=sys.stderr)
            return 4
        out = {"network": net.to_dict(), "command": plan.shell_preview,
               "returncode": proc.returncode,
               "devices": [d.to_dict() for d in devices]}
        if proc.returncode == 127:
            out["note"] = "nmap non è installato su questo sistema."
        _print(out)
        return 0 if proc.returncode == 0 else 1
    if args.what == "bluetooth":
        plan, devices, err = ex.scan_bluetooth(seconds=args.seconds)
        print(f"[comando] {plan.shell_preview}", file=sys.stderr)
        out = {"command": plan.shell_preview,
               "devices": [d.to_dict() for d in devices]}
        if err:
            out["note"] = err
        _print(out)
        return 0 if not err else 2
    return 2


def cmd_report(args) -> int:
    proj = Project.load(args.base, args.project)
    if args.format == "json":
        print(report_mod.to_json(proj))
    elif args.format == "html":
        print(report_mod.to_html(proj))
    elif args.format == "pdf":
        ok = report_mod.to_pdf(proj, args.out or "report.pdf")
        if not ok:
            print("PDF non disponibile (reportlab non installato). Usa json/html.",
                  file=sys.stderr)
            return 2
        print(f"PDF scritto in {args.out or 'report.pdf'}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberdistro-sc",
        description="CyberDistro Security Center — front-end guidato e sicuro.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--base", default=DEFAULT_BASE,
                   help="directory dei progetti (default: %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="stato sistema + capacità strumenti").set_defaults(func=cmd_doctor)
    sub.add_parser("catalog", help="elenca strumenti per categoria").set_defaults(func=cmd_catalog)

    pe = sub.add_parser("explain", help="spiega uno strumento")
    pe.add_argument("tool_id")
    pe.set_defaults(func=cmd_explain)

    pn = sub.add_parser("project", help="gestione progetti")
    psub = pn.add_subparsers(dest="pcmd", required=True)
    pnew = psub.add_parser("new", help="crea un progetto con proprietario e ambito")
    pnew.add_argument("name")
    pnew.add_argument("--owner", required=True)
    pnew.add_argument("--scope", nargs="*", help="target autorizzati (IP/CIDR/host)")
    pnew.add_argument("--note", default="")
    pnew.set_defaults(func=cmd_project_new)

    pr = sub.add_parser("run", help="esegui un'operazione guidata")
    pr.add_argument("tool_id")
    pr.add_argument("--project", required=True)
    pr.add_argument("--target", required=True)
    pr.add_argument("--profile", default="discovery")
    pr.add_argument("--mode", default="beginner")
    pr.add_argument("--extra", nargs="*", help="(expert) flag aggiuntivi")
    pr.add_argument("--dry-run", action="store_true", help="mostra il comando senza eseguirlo")
    pr.add_argument("--yes", action="store_true", help="conferma operazioni invasive")
    pr.set_defaults(func=cmd_run)

    px = sub.add_parser("explore", help="(principianti) chi c'è sulla rete / Bluetooth")
    px.add_argument("what", choices=["networks", "network", "bluetooth"],
                    help="networks: elenca reti locali; network: dispositivi sulla "
                         "rete locale; bluetooth: dispositivi vicini")
    px.add_argument("--interface", help="interfaccia di rete da esplorare")
    px.add_argument("--seconds", type=int, default=8, help="durata ascolto Bluetooth")
    px.add_argument("--yes", action="store_true",
                    help="confermo: è la mia rete o sono autorizzato a osservarla")
    px.set_defaults(func=cmd_explore)

    prep = sub.add_parser("report", help="genera un report")
    prep.add_argument("project")
    prep.add_argument("--format", choices=["json", "html", "pdf"], default="json")
    prep.add_argument("--out")
    prep.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
