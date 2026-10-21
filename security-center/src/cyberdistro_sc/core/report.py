"""Report generation.

JSON is the canonical, machine-readable format (implemented and tested here).
HTML is produced from the same structure. PDF is on the roadmap and is produced
via reportlab when the optional dependency is present; otherwise the generator
says so honestly rather than pretending.

Every report explicitly separates:
  * data detected by tools,
  * interpretations/suggestions (and whether they came from an AI assistant),
so a reader can tell facts from inferences.
"""

from __future__ import annotations

import html
import json
import time
from .project import Project


def build_structure(project: Project) -> dict:
    return {
        "report_version": 1,
        "generated_at": time.time(),
        "project": project.auth.to_dict(),
        "disclaimer": (
            "Declared scope records the operator's stated authorization; it is "
            "not a legal or technical guarantee. Operator is responsible."
        ),
        "operations": [e.to_dict() for e in project.log],
        "findings_detected": [
            f.to_dict() for f in project.findings if f.source == "tool"
        ],
        "interpretations": [
            f.to_dict() for f in project.findings if f.source in ("ai", "analyst")
        ],
        "summary": _summarize(project),
    }


def _summarize(project: Project) -> dict:
    by_sev: dict[str, int] = {}
    for f in project.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "operations": len(project.log),
        "findings_total": len(project.findings),
        "findings_by_severity": by_sev,
    }


def to_json(project: Project) -> str:
    return json.dumps(build_structure(project), indent=2, ensure_ascii=False)


def to_html(project: Project) -> str:
    s = build_structure(project)
    a = s["project"]
    rows = []
    for f in project.findings:
        rows.append(
            "<tr><td>{sev}</td><td>{conf}</td><td>{src}</td>"
            "<td>{title}</td><td>{detail}</td></tr>".format(
                sev=html.escape(f.severity), conf=html.escape(f.confidence),
                src=html.escape(f.source), title=html.escape(f.title),
                detail=html.escape(f.detail),
            )
        )
    ops = "".join(
        "<li><code>{cmd}</code> → rc={rc}</li>".format(
            cmd=html.escape(e.command), rc=e.returncode)
        for e in project.log
    )
    return f"""<!doctype html><html lang="it"><head><meta charset="utf-8">
<title>Report — {html.escape(a['project'])}</title>
<style>body{{font-family:Inter,system-ui,sans-serif;margin:2rem;max-width:60rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem}}
.disc{{background:#fff8e1;border:1px solid #e6c200;padding:.8rem;border-radius:.4rem}}</style>
</head><body>
<h1>Report di sicurezza — {html.escape(a['project'])}</h1>
<p><b>Proprietario:</b> {html.escape(a['owner'])}<br>
<b>Ambito autorizzato:</b> {html.escape(', '.join(a['scope']) or '—')}</p>
<p class="disc">{html.escape(s['disclaimer'])}</p>
<h2>Operazioni ({len(project.log)})</h2><ul>{ops}</ul>
<h2>Risultati</h2>
<table><tr><th>Gravità</th><th>Confidenza</th><th>Fonte</th><th>Titolo</th><th>Dettaglio</th></tr>
{''.join(rows)}</table>
<p><small>Generato il {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['generated_at']))}</small></p>
</body></html>"""


def to_pdf(project: Project, path: str) -> bool:
    """Write a PDF if reportlab is available. Returns True on success.

    Returns False (without raising) when reportlab is not installed, so callers
    can fall back to HTML/JSON and tell the user honestly.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
    except Exception:
        return False
    s = build_structure(project)
    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    y = height - 2 * cm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2 * cm, y, f"Report — {s['project']['project']}")
    y -= 1 * cm
    c.setFont("Helvetica", 10)
    for line in [
        f"Proprietario: {s['project']['owner']}",
        f"Ambito: {', '.join(s['project']['scope']) or '—'}",
        f"Operazioni: {s['summary']['operations']}  "
        f"Risultati: {s['summary']['findings_total']}",
        "",
        s["disclaimer"],
    ]:
        c.drawString(2 * cm, y, line[:100])
        y -= 0.6 * cm
    c.showPage()
    c.save()
    return True
