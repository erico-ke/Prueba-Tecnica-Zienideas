"""Modo exploración: python -m auditor.explore

Analiza lo que los permisos concedidos realmente permiten ver y busca discrepancias.
Solo lectura (GET).
"""
import argparse
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


from .auth import AuthError, get_token, token_claims
from .config import ConfigError, load_config
from .graph import GraphClient, GraphError
from .models import AuditResult, Finding, SectionResult, Severity
from .report import anonymize, severity_counts, write_csv, write_html, write_json
from .rules import exploration as rx
from .rules.consent import consent_findings

BETA = "https://graph.microsoft.com/beta/"

# (endpoint, qué es, permisos de aplicación documentados por Microsoft)
PROBES = [
    ("users?$top=1", "Usuarios", ("User.Read.All", "User.ReadBasic.All", "Directory.Read.All")),
    ("groups?$top=1", "Grupos", ("Group.Read.All", "GroupMember.Read.All", "Directory.Read.All")),
    ("roleManagement/directory/roleAssignments?$top=1", "Roles de administrador", ("RoleManagement.Read.Directory", "RoleManagement.Read.All", "Directory.Read.All")),
    ("reports/authenticationMethods/userRegistrationDetails?$top=1", "Registro de MFA", ("AuditLog.Read.All",)),
    ("auditLogs/signIns?$top=1", "Registros de inicio de sesión", ("AuditLog.Read.All",)),
    ("subscribedSkus", "Licencias", ("LicenseAssignment.Read.All", "Organization.Read.All", "Directory.Read.All")),
    ("organization", "Organización", ("Organization.Read.All", "Directory.Read.All")),
    ("domains", "Dominios", ("Domain.Read.All", "Directory.Read.All")),
    ("policies/identitySecurityDefaultsEnforcementPolicy", "Security defaults", ("Policy.Read.All",)),
    ("applications?$top=1", "Registros de aplicaciones", ("Application.Read.All", "Directory.Read.All")),
    ("servicePrincipals?$top=1", "Aplicaciones empresariales", ("Application.Read.All", "Directory.Read.All")),
    ("directory/administrativeUnits", "Unidades administrativas", ("AdministrativeUnit.Read.All", "Directory.Read.All")),
    ("identityGovernance/accessReviews/definitions", "Revisiones de acceso", ("AccessReview.Read.All",)),
    ("identityGovernance/termsOfUse/agreements", "Términos de uso", ("Agreement.Read.All",)),
    ("identityProtection/riskyUsers", "Usuarios en riesgo", ("IdentityRiskyUser.Read.All",)),
    ("identityProtection/riskyServicePrincipals", "Apps en riesgo", ("IdentityRiskyServicePrincipal.Read.All",)),
    (BETA + "reports/healthMonitoring/alerts", "Alertas de salud de Entra", ("HealthMonitoringAlert.Read.All",)),
    ("search/acronyms", "Acrónimos (Microsoft Search)", ("Acronym.Read.All",)),
    ("identity/apiConnectors", "API connectors (External ID)", ("APIConnectors.Read.All",)),
    (BETA + "servicePrincipals/microsoft.graph.agentIdentity", "Identidades de agentes IA", ("AgentIdentity.Read.All",)),
    (BETA + "agentRegistry/agentInstances", "Registro de agentes IA", ("AgentInstance.Read.All",)),
]


def run_probes(client: GraphClient) -> list[rx.Probe]:
    probes = []
    for endpoint, label, perms in PROBES:
        try:
            data = client.get(endpoint)
            count = len(data["value"]) if "value" in data else None
            probes.append(rx.Probe(endpoint.replace(BETA, "beta/"), label, perms, 200, count=count))
        except GraphError as e:
            probes.append(rx.Probe(endpoint.replace(BETA, "beta/"), label, perms, e.status, e.code, e.message))
    return probes


def try_all(client: GraphClient, path: str, **params):
    try:
        return list(client.get_all(path, params=params or None))
    except GraphError:
        return None


@dataclass
class Analysis:
    result: AuditResult
    roles: list
    delegated: list
    probes: list
    generated: datetime


def analyze_tenant(config, token: str, progress=print) -> Analysis:
    """Ejecuta todo el análisis. Lo usan la línea de comandos y la interfaz gráfica."""
    client = GraphClient(token)
    now = datetime.now(timezone.utc)
    roles = token_claims(token).get("roles", [])
    progress(f"Permisos en el token: {len(roles)}. Probando endpoints...")
    probes = run_probes(client)

    progress("Leyendo organización y aplicaciones...")
    org_list = try_all(client, "organization")
    org = org_list[0] if org_list else None
    sps = try_all(client, "servicePrincipals", **{"$top": "999"})
    apps = try_all(client, "applications", **{"$top": "999"})
    admin_units = try_all(client, "directory/administrativeUnits")
    reviews = try_all(client, "identityGovernance/accessReviews/definitions")

    # Consentimientos de todas las apps; permisos de aplicación solo de las que no son de Microsoft
    app_perms, grants, own_delegated = {}, {}, []
    if sps:
        role_names = {(sp["id"], r["id"]): r.get("value") for sp in sps for r in sp.get("appRoles") or []}
        for i, sp in enumerate(sps, 1):
            if i % 20 == 0:
                progress(f"Revisando permisos y consentimientos: {i}/{len(sps)} apps...")
            grants[sp["id"]] = try_all(client, f"servicePrincipals/{sp['id']}/oauth2PermissionGrants") or []
            if rx.origin(sp, config.tenant_id) == "microsoft":
                continue
            assignments = try_all(client, f"servicePrincipals/{sp['id']}/appRoleAssignments") or []
            app_perms[sp["id"]] = [f"{a.get('resourceDisplayName')}: {role_names.get((a['resourceId'], a['appRoleId']), a['appRoleId'])}"
                                   for a in assignments]
            if sp.get("appId") == config.client_id:
                own_delegated = sorted({s for g in grants[sp["id"]] for s in (g.get("scope") or "").split()})

    owners = {}
    for app in apps or []:
        o = try_all(client, f"applications/{app['id']}/owners", **{"$select": "id"})
        owners[app["id"]] = len(o) if o is not None else None

    def section(category: str, findings: list[Finding], note: str = None) -> SectionResult:
        real = any(f.severity is not Severity.INFO for f in findings)
        return SectionResult(category, "Hallazgos" if real else "OK", findings, note)

    na = lambda c, why: SectionResult(c, "No disponible", note=why)
    sections = [
        section("Concesiones sospechosas", consent_findings(sps, config.tenant_id, app_perms, grants, config.client_id, now))
        if sps is not None else na("Concesiones sospechosas", "Requiere Application.Read.All"),
        section("Permisos de la herramienta", rx.own_permission_findings(roles, own_delegated)),
        section("Acceso real vs. permisos", rx.access_findings(probes, roles)),
        section("Organización", rx.organization_findings(org, now)) if org else na("Organización", "Sin acceso a /organization"),
        section("Aplicaciones", (rx.app_registration_findings(apps, owners, now) if apps is not None else [])
                + (rx.enterprise_app_findings(sps, config.tenant_id, app_perms, grants, config.client_id, now) if sps is not None else []))
        if apps is not None or sps is not None else na("Aplicaciones", "Requiere Application.Read.All"),
        section("Gobierno", rx.governance_findings(admin_units, reviews)),
    ]

    summary = {
        "Permisos de aplicación": len(roles),
        "De escritura": sum(rx.is_write(r) for r in roles),
        "Permiso necesario (Application.Read.All)": "Sí" if "Application.Read.All" in roles else "No",
        "Endpoints accesibles": f"{sum(p.ok for p in probes)} / {len(probes)}",
    }
    if org:
        summary["Entra ID P1/P2"] = "Sí" if not any(f.id == "ORG-001" for f in rx.organization_findings(org, now)) else "No"
    if sps is not None:
        summary["Aplicaciones empresariales"] = len(sps)
    if apps is not None:
        summary["Registros de aplicaciones"] = len(apps)
    return Analysis(AuditResult(summary, sections, None), roles, own_delegated, probes, now)


def save_reports(result: AuditResult, config, generated: datetime, output_dir: str, anonymized: bool) -> list[Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    local = generated.astimezone()
    meta = {"tenant_id": config.tenant_id, "generado": local.strftime("%Y-%m-%d %H:%M"), "anonimizado": anonymized}
    paths = [out / f"permisos-{local:%Y%m%d-%H%M%S}.{ext}" for ext in ("html", "json", "csv")]
    write_html(result, meta, paths[0])
    write_json(result, meta, paths[1])
    write_csv(result, paths[2])
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Detector de concesiones de permisos fraudulentas en un tenant de Microsoft 365 (solo lectura)")
    parser.add_argument("-o", "--output-dir", default="reports")
    parser.add_argument("--anonymize", action="store_true")
    parser.add_argument("--gui", action="store_true", help="abre la interfaz gráfica")
    args = parser.parse_args()

    if args.gui:
        from .gui import run
        return run(args.anonymize, args.output_dir)

    try:
        config = load_config()
        token = get_token(config)
    except (ConfigError, AuthError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    analysis = analyze_tenant(config, token)
    result = anonymize(analysis.result) if args.anonymize else analysis.result
    for k, v in result.summary.items():
        print(f"  {k}: {v}")
    print("Hallazgos: " + ", ".join(f"{k} {v}" for k, v in severity_counts(result.sections).items()))
    paths = save_reports(result, config, analysis.generated, args.output_dir, args.anonymize)
    print("Informe:\n" + "\n".join(f"  {p}" for p in paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
