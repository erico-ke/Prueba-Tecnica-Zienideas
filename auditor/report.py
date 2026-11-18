"""Generación del informe de hallazgos: HTML (lectura), JSON y CSV (exportación)."""
import csv
import json
import re
from dataclasses import asdict, replace
from html import escape
from pathlib import Path


from .models import AuditResult, Finding, SectionResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "#8b0000",
    Severity.HIGH: "#d9534f",
    Severity.MEDIUM: "#e69500",
    Severity.LOW: "#3a87ad",
    Severity.INFO: "#777777",
}

_EMAIL = re.compile(r"([A-Za-z0-9])[A-Za-z0-9._%+#-]*@")


def anonymize_text(text: str) -> str:
    """juan.perez@contoso.com -> j***@contoso.com"""
    return _EMAIL.sub(r"\1***@", text)


def anonymize(result: AuditResult) -> AuditResult:
    sections = [
        replace(s, findings=[replace(f, affected=[anonymize_text(a) for a in f.affected]) for f in s.findings])
        for s in result.sections
    ]
    return replace(result, sections=sections)


def all_findings(sections: list[SectionResult]) -> list[Finding]:
    return sorted((f for s in sections for f in s.findings), key=lambda f: (f.severity.rank, f.id))


def severity_counts(sections: list[SectionResult]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in all_findings(sections):
        counts[f.severity.value] += 1
    return counts


# --------------------------------------------------------------------------- JSON
def write_json(result: AuditResult, meta: dict, path: Path) -> None:
    data = {
        **meta,
        "resumen": result.summary,
        "hallazgos_por_severidad": severity_counts(result.sections),
        "areas": [asdict(s) for s in result.sections],
        "licencias": result.licenses,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


# --------------------------------------------------------------------------- CSV
def write_csv(result: AuditResult, path: Path) -> None:
    """Una fila por objeto afectado: fácil de filtrar en Excel o importar en un ticketing."""
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["id", "severidad", "area", "hallazgo", "objeto_afectado", "recomendacion"])
        for f in all_findings(result.sections):
            for a in f.affected or [""]:
                w.writerow([f.id, f.severity.value, f.category, f.title, a, f.recommendation])


# --------------------------------------------------------------------------- HTML
def write_html(result: AuditResult, meta: dict, path: Path) -> None:
    e = escape
    counts = severity_counts(result.sections)

    summary_html = "".join(
        f'<div class="tile"><b>{e(str(v))}</b><span>{e(k)}</span></div>' for k, v in result.summary.items())
    sev_html = "".join(
        f'<div class="tile" style="border-color:{SEVERITY_COLORS[Severity(k)]}"><b>{v}</b><span>{e(k)}</span></div>'
        for k, v in counts.items())

    status_cls = {"OK": "ok", "Hallazgos": "fail", "No disponible": "na"}
    sections_rows = "".join(
        f"<tr><td>{e(s.category)}</td><td class='{status_cls[s.status]}'>{e(s.status)}</td>"
        f"<td>{len([f for f in s.findings if f.severity is not Severity.INFO])}</td><td>{e(s.note or '')}</td></tr>"
        for s in result.sections)

    def finding_html(f: Finding) -> str:
        color = SEVERITY_COLORS[f.severity]
        affected = ""
        if f.affected:
            items = "".join(f"<li>{e(a)}</li>" for a in f.affected)
            affected = f"<details><summary>Objetos afectados ({len(f.affected)})</summary><ul>{items}</ul></details>"
        return (f'<section class="finding" style="border-left-color:{color}">'
                f'<h3><span class="sev" style="background:{color}">{e(f.severity.value)}</span> {e(f.title)} '
                f'<small>{e(f.id)} · {e(f.category)}</small></h3>'
                f"<p>{e(f.description)}</p><p><b>Qué hacer:</b> {e(f.recommendation)}</p>{affected}</section>")

    findings_html = "".join(finding_html(f) for f in all_findings(result.sections)) \
        or "<p>No se han encontrado hallazgos.</p>"

    licenses_html = ""
    if result.licenses:
        rows = "".join(
            f"<tr><td>{e(str(l['sku']))}</td><td>{e(str(l['estado']))}</td><td>{l['contratadas']}</td>"
            f"<td>{l['asignadas']}</td><td>{l['en_aviso']}</td><td>{l['suspendidas']}</td></tr>"
            for l in result.licenses)
        licenses_html = ("<h2>Licencias</h2><table><tr><th>SKU</th><th>Estado</th><th>Contratadas</th>"
                         f"<th>Asignadas</th><th>En aviso</th><th>Suspendidas</th></tr>{rows}</table>")

    html = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoría del tenant</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 980px; margin: 2rem auto; padding: 0 1rem; color: #1d2433; background: #fff; }}
 h1 {{ margin-bottom: .2rem; }} .meta {{ color: #666; margin-top: 0; }}
 .tiles {{ display: flex; gap: .6rem; flex-wrap: wrap; }}
 .tile {{ border-top: 4px solid #1d2433; padding: .6rem .9rem; background: #f4f5f7; min-width: 120px; }}
 .tile b {{ display: block; font-size: 1.5rem; }} .tile span {{ font-size: .85rem; color: #555; }}
 table {{ border-collapse: collapse; width: 100%; font-size: .92rem; }}
 td, th {{ border-bottom: 1px solid #ddd; padding: .4rem; text-align: left; vertical-align: top; }}
 .ok {{ color: #2e7d32; font-weight: 600; }} .fail {{ color: #c62828; font-weight: 600; }} .na {{ color: #8a6d3b; font-weight: 600; }}
 .finding {{ border-left: 5px solid; padding: .4rem 1rem; margin: 1rem 0; background: #fafafa; }}
 .finding h3 {{ font-size: 1.05rem; }}
 .sev {{ color: #fff; padding: .1rem .5rem; border-radius: 4px; font-size: .8rem; }}
 small {{ color: #777; font-weight: normal; }}
</style></head><body>
<h1>Auditoría del tenant</h1>
<p class="meta">Tenant <code>{e(meta['tenant_id'])}</code> · Datos de {e(meta['generado'])}
{' · <b>Datos personales anonimizados</b>' if meta.get('anonimizado') else ''}</p>
<h2>Resumen del tenant</h2><div class="tiles">{summary_html}</div>
<h2>Hallazgos por severidad</h2><div class="tiles">{sev_html}</div>
<h2>Estado por área</h2>
<table><tr><th>Área</th><th>Estado</th><th>Hallazgos</th><th>Notas / limitaciones</th></tr>{sections_rows}</table>
<h2>Hallazgos</h2>{findings_html}
{licenses_html}
</body></html>"""
    path.write_text(html, encoding="utf-8")
