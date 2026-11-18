"""Detector de concesiones de permisos fraudulentas (illicit consent grant / consent phishing).

Cada aplicación que no es de Microsoft recibe una puntuación sumando indicadores explícitos.
Ningún indicador por sí solo prueba un fraude; la combinación es lo que lo hace sospechoso
(p. ej. app de terceros + sin verificar + nueva + lee el correo de todos = patrón clásico).

    Puntos  Indicador
      +1    App de otro tenant (tercero)
      +2    Editor no verificado (solo terceros)
      +3    Nombre que imita a Microsoft (Office, Outlook, Azure, Teams...), solo apps de otros tenants
      +3    Permisos de aplicación de alto impacto (escritura o contenido sensible)
      +2    Permisos delegados sensibles consentidos (correo, archivos, directorio...)
      +1    ...consentidos para toda la organización
      +1    ...con acceso persistente (offline_access)
      +3    Credenciales (secretos/certificados) añadidas a la app empresarial de un tercero
      +1    Creada hace menos de 30 días
      +1    URL de respuesta http:// (no localhost)

    Severidad:  >= 8 Crítica · >= 5 Alta · >= 3 Media · < 3 no se reporta (solo inventario)
"""
from datetime import datetime, timedelta

from ..dates import parse_graph_datetime
from ..models import Finding, Severity
from .exploration import RISKY_DELEGATED, SENSITIVE_READ, insecure_redirects, is_write, origin

IMPERSONATION_WORDS = ("microsoft", "office", "outlook", "azure", "teams", "onedrive", "sharepoint",
                       "windows", "exchange", "defender", "entra", "m365", "o365")


def score_app(sp: dict, tenant_id: str, app_permissions: list[str], grants: list[dict],
              now: datetime) -> tuple[int, list[str]]:
    """Devuelve (puntuación, motivos) de una aplicación empresarial."""
    org = origin(sp, tenant_id)
    if org == "microsoft":
        return 0, []
    score, reasons = 0, []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(f"+{points} {reason}")

    if org in ("tercero", "desconocido"):
        add(1, "aplicación de otro tenant")
        if not (sp.get("verifiedPublisher") or {}).get("verifiedPublisherId"):
            add(2, "editor no verificado")
        if sp.get("passwordCredentials") or sp.get("keyCredentials"):
            add(3, "credenciales añadidas a la app de un tercero (posible puerta trasera)")

    name = (sp.get("displayName") or "").lower()
    imitated = [w for w in IMPERSONATION_WORDS if w in name]
    if imitated and org != "propia":  # una app propia llamada "M365-..." es habitual, no suplantación
        add(3, f"nombre que imita a Microsoft ('{imitated[0]}') sin ser de Microsoft")

    risky_app = sorted(p for p in app_permissions if is_write(p) or p.split(": ")[-1] in SENSITIVE_READ)
    if risky_app:
        add(3, f"permisos de aplicación de alto impacto: {', '.join(risky_app)}")

    delegated = set()
    org_wide, users = False, set()
    for g in grants:
        scopes = set((g.get("scope") or "").split())
        risky = scopes & RISKY_DELEGATED
        if risky:
            delegated |= risky | (scopes & {"offline_access"})
            if g.get("consentType") == "AllPrincipals":
                org_wide = True
            elif g.get("principalId"):
                users.add(g["principalId"])
    if delegated - {"offline_access"}:
        who = "toda la organización" if org_wide else f"{len(users)} usuario(s)"
        add(2, f"permisos delegados sensibles ({', '.join(sorted(delegated - {'offline_access'}))}) consentidos por {who}")
        if org_wide:
            add(1, "consentimiento para toda la organización")
        if "offline_access" in delegated:
            add(1, "acceso persistente (offline_access)")

    created = parse_graph_datetime(sp.get("createdDateTime"))
    if created and now - created <= timedelta(days=30):
        add(1, f"creada hace {(now - created).days} días")
    if insecure_redirects(sp):
        add(1, f"URL de respuesta sin cifrar: {', '.join(insecure_redirects(sp))}")
    return score, reasons


def severity_for(score: int):
    if score >= 8:
        return Severity.CRITICAL
    if score >= 5:
        return Severity.HIGH
    if score >= 3:
        return Severity.MEDIUM
    return None


def consent_findings(sps: list[dict], tenant_id: str, app_permissions: dict[str, list[str]],
                     grants: dict[str, list[dict]], own_app_id: str, now: datetime) -> list[Finding]:
    scored = []
    for sp in sps:
        if sp.get("appId") == own_app_id:
            continue  # la propia herramienta se evalúa en "Permisos de la herramienta"
        score, reasons = score_app(sp, tenant_id, app_permissions.get(sp["id"], []), grants.get(sp["id"], []), now)
        if severity_for(score):
            scored.append((score, sp, reasons))

    findings = []
    for i, (score, sp, reasons) in enumerate(sorted(scored, key=lambda x: -x[0]), 1):
        findings.append(Finding(
            id=f"CON-{i:03d}", category="Concesiones sospechosas", severity=severity_for(score),
            title=f"{sp.get('displayName')} — puntuación de riesgo {score}",
            description=(f"Aplicación [{origin(sp, tenant_id)}] con indicadores de concesión de permisos fraudulenta "
                         "o excesiva. Cada línea de 'objetos afectados' es un indicador con su peso."),
            recommendation=("Confirmar con el propietario de negocio que la app es legítima. Si no lo es: revocar sus "
                            "consentimientos y asignaciones, deshabilitar la app empresarial, revocar las sesiones de los "
                            "usuarios que consintieron y revisar el registro de auditoría ('Consent to application')."),
            affected=reasons,
        ))

    # Credenciales en apps de Microsoft: técnica conocida de persistencia (p. ej. campaña Solorigate)
    backdoors = [sp.get("displayName") for sp in sps
                 if origin(sp, tenant_id) == "microsoft" and (sp.get("passwordCredentials") or sp.get("keyCredentials"))]
    if backdoors:
        findings.append(Finding(
            id="CON-MS1", category="Concesiones sospechosas", severity=Severity.HIGH,
            title=f"{len(backdoors)} aplicaciones de Microsoft con credenciales añadidas en este tenant",
            description=("Las apps de primera parte de Microsoft no necesitan credenciales creadas por el cliente. "
                         "Añadirlas es una técnica de persistencia conocida para heredar sus permisos."),
            recommendation="Verificar quién las añadió (registro de auditoría) y eliminarlas si no están justificadas.",
            affected=sorted(backdoors),
        ))

    # Apps legítimas de Microsoft (Graph Explorer, PowerShell...) con permisos delegados peligrosos:
    # no es fraude, pero un token robado de esa sesión da ese poder
    powerful = []
    for sp in sps:
        if origin(sp, tenant_id) != "microsoft":
            continue
        risky = {s for g in grants.get(sp["id"], []) for s in (g.get("scope") or "").split()} & RISKY_DELEGATED
        if risky:
            powerful.append(f"{sp.get('displayName')}: {', '.join(sorted(risky))}")
    if powerful:
        findings.append(Finding(
            id="CON-MS2", category="Concesiones sospechosas", severity=Severity.MEDIUM,
            title=f"{len(powerful)} herramientas de Microsoft con permisos delegados de alto riesgo consentidos",
            description=("Apps legítimas (p. ej. Graph Explorer) a las que un usuario ha concedido permisos amplios. "
                         "El consentimiento persiste tras usar la herramienta."),
            recommendation="Revocar el consentimiento cuando no se necesite y restringir quién puede consentir permisos de administrador.",
            affected=sorted(powerful),
        ))
    return findings
