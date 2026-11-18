"""Reglas del modo exploración: funciones puras sobre lo que los permisos disponibles dejan ver.

Áreas:
  - Permisos de la propia herramienta (¿cumple "solo lectura" y mínimo privilegio?)
  - Acceso real frente a permisos (discrepancias)
  - Organización (licencias, contactos de seguridad, dominios)
  - Aplicaciones: registros (secretos) y aplicaciones empresariales (terceros, permisos)
  - Gobierno (revisiones de acceso, unidades administrativas)
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from ..dates import parse_graph_datetime
from ..models import Finding, Severity

# Único permiso que necesita el detector (lee aplicaciones, sus permisos y consentimientos)
REQUIRED_PERMISSIONS = ("Application.Read.All",)

# Permisos de solo lectura que dan acceso a contenido especialmente sensible
SENSITIVE_READ = {
    "AiEnterpriseInteraction.Read.All": "lee las interacciones con Copilot (prompts y respuestas) de todos los usuarios",
    "Mail.Read": "lee el correo de todos los buzones",
    "Mail.ReadBasic.All": "lee metadatos del correo de todos los buzones",
    "Files.Read.All": "lee todos los archivos de OneDrive/SharePoint",
    "Sites.Read.All": "lee todos los sitios de SharePoint",
    "Chat.Read.All": "lee todos los chats de Teams",
    "ChannelMessage.Read.All": "lee todos los mensajes de canales de Teams",
    "Directory.Read.All": "lee todo el directorio",
    "full_access_as_app": "acceso completo a todos los buzones de Exchange",
}

# Permisos delegados peligrosos si se consienten para toda la organización
RISKY_DELEGATED = {"Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All",
                   "Sites.Read.All", "Sites.ReadWrite.All", "Directory.AccessAsUser.All",
                   "Directory.ReadWrite.All", "User.ReadWrite.All", "EWS.AccessAsUser.All", "full_access_as_user"}

# Tenants propietarios de las aplicaciones de primera parte de Microsoft
# (cdc5aeea: Graph Explorer, Microsoft Graph Command Line Tools; descubierto en la primera ejecución real)
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47",
                     "cdc5aeea-15c5-4db6-b079-fcadd2505dc2"}

ENTRA_PREMIUM_PLANS = {"41781fb2-bc02-4b7c-bd55-b576c07bb09d": "Entra ID P1",
                       "eec0eb4f-6444-4f95-aba0-50c24d67f998": "Entra ID P2"}

LICENSE_ERROR_CODES = ("TenantNotLicensed", "RequestFromNonPremiumTenant", "not licensed", "premium license")


@dataclass
class Probe:
    """Resultado de probar un endpoint de Graph."""
    endpoint: str
    label: str
    permissions: tuple          # permisos de aplicación que documenta Microsoft para el endpoint
    status: int
    code: str = ""
    message: str = ""
    count: Optional[int] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def unlicensed(self) -> bool:
        text = f"{self.code} {self.message}".lower()
        return any(m.lower() in text for m in LICENSE_ERROR_CODES)


def is_write(permission: str) -> bool:
    return any(m in permission for m in (".ReadWrite", ".Write", ".Manage", "FullControl", ".Send"))


def origin(sp: dict, tenant_id: str) -> str:
    owner = sp.get("appOwnerOrganizationId")
    if owner in MICROSOFT_TENANTS:
        return "microsoft"
    if owner == tenant_id:
        return "propia"
    return "tercero" if owner else "desconocido"


# ------------------------------------------------------------------ Permisos propios
def own_permission_findings(token_roles: list[str], delegated_scopes: list[str]) -> list[Finding]:
    roles = sorted(set(token_roles))
    findings: list[Finding] = []

    writes = [r for r in roles if is_write(r)]
    if writes:
        findings.append(Finding(
            id="PRM-001", category="Permisos de la herramienta", severity=Severity.HIGH,
            title=f"La herramienta de auditoría tiene {len(writes)} permisos de escritura",
            description=("Una herramienta de auditoría solo necesita leer. Con estos permisos, quien obtenga el "
                         "CLIENT_SECRET (p. ej. desde un .env filtrado) puede modificar el tenant sin MFA."),
            recommendation="Quitar los permisos *.ReadWrite.* de la app. El código de la herramienta solo hace GET.",
            affected=writes,
        ))

    sensitive = [f"{r}: {SENSITIVE_READ[r]}" for r in roles if r in SENSITIVE_READ]
    if sensitive:
        findings.append(Finding(
            id="PRM-002", category="Permisos de la herramienta", severity=Severity.HIGH,
            title=f"{len(sensitive)} permisos de lectura de contenido sensible",
            description="Dan acceso a datos personales o confidenciales de toda la organización (RGPD).",
            recommendation="Retirarlos: el detector no los necesita.",
            affected=sensitive,
        ))

    missing = [p for p in REQUIRED_PERMISSIONS if p not in roles]
    if missing:
        findings.append(Finding(
            id="PRM-003", category="Permisos de la herramienta", severity=Severity.MEDIUM,
            title=f"Falta el permiso necesario para el detector: {', '.join(missing)}",
            description="Sin él no se pueden leer las aplicaciones, sus permisos ni los consentimientos.",
            recommendation="Conceder Application.Read.All (permiso de aplicación, solo lectura).",
            affected=missing,
        ))

    unneeded = [r for r in roles if r not in REQUIRED_PERMISSIONS and not is_write(r) and r not in SENSITIVE_READ]
    if unneeded:
        findings.append(Finding(
            id="PRM-004", category="Permisos de la herramienta", severity=Severity.LOW,
            title=f"{len(unneeded)} permisos que el detector no necesita",
            description="Cada permiso innecesario amplía lo que se expone si se filtra la credencial (mínimo privilegio).",
            recommendation="Retirar los permisos que no use ninguna comprobación.",
            affected=unneeded,
        ))

    if delegated_scopes:
        findings.append(Finding(
            id="PRM-005", category="Permisos de la herramienta", severity=Severity.LOW,
            title=f"{len(delegated_scopes)} permisos delegados que la herramienta nunca usa",
            description="La herramienta se autentica como aplicación (sin usuario): los permisos delegados no se usan.",
            recommendation="Quitarlos del registro de la app.",
            affected=sorted(delegated_scopes),
        ))
    return findings


# --------------------------------------------------------------- Acceso vs permisos
def access_findings(probes: list[Probe], token_roles: list[str]) -> list[Finding]:
    roles = set(token_roles)
    findings: list[Finding] = []

    beyond = [f"{p.label} ({p.endpoint}): accesible sin {' / '.join(p.permissions)}"
              for p in probes if p.ok and not roles & set(p.permissions)]
    if beyond:
        findings.append(Finding(
            id="ACC-001", category="Acceso real vs. permisos", severity=Severity.MEDIUM,
            title=f"{len(beyond)} endpoints accesibles sin el permiso que documenta Microsoft",
            description=("La app lee datos para los que no tiene concedido el permiso documentado: otro permiso "
                         "(o el acceso por defecto) da más alcance del que su nombre sugiere. Revisar permisos por "
                         "su nombre subestima lo que una app puede ver."),
            recommendation="Evaluar el alcance de una app probando lo que realmente puede leer, no solo por la lista de permisos.",
            affected=beyond,
        ))

    dormant = [f"{p.label}: {', '.join(sorted(roles & set(p.permissions)))} → {p.status} {p.code}"
               for p in probes if not p.ok and roles & set(p.permissions) and p.unlicensed]
    if dormant:
        findings.append(Finding(
            id="ACC-002", category="Acceso real vs. permisos", severity=Severity.LOW,
            title=f"{len(dormant)} permisos concedidos que hoy no funcionan por falta de licencia",
            description=("Ahora no dan acceso, pero se activarán sin aviso si el tenant contrata la licencia "
                         "(p. ej. Entra ID P1/P2): privilegio latente."),
            recommendation="Retirarlos; si se necesitan en el futuro, concederlos entonces.",
            affected=dormant,
        ))

    broken = [f"{p.label}: {', '.join(sorted(roles & set(p.permissions)))} → {p.status} {p.code}"
              for p in probes if not p.ok and roles & set(p.permissions) and not p.unlicensed]
    if broken:
        findings.append(Finding(
            id="ACC-003", category="Acceso real vs. permisos", severity=Severity.INFO,
            title=f"{len(broken)} permisos concedidos sin uso posible (función no habilitada o servicio no disponible)",
            description="El permiso existe pero el servicio responde con error (función desactivada, preview no disponible...).",
            recommendation="Retirarlos si no se usa la función.",
            affected=broken,
        ))

    matrix = [f"{'✔' if p.ok else '✘'} {p.status} {p.label} — {p.endpoint}"
              + (f" ({p.count} elementos)" if p.ok and p.count is not None else "")
              + ("" if p.ok else f" [{p.code}]")
              for p in probes]
    findings.append(Finding(
        id="ACC-004", category="Acceso real vs. permisos", severity=Severity.INFO,
        title=f"Matriz de acceso: {sum(p.ok for p in probes)} de {len(probes)} endpoints accesibles",
        description="Resultado de probar cada endpoint relevante con el token de la herramienta.",
        recommendation="Usar como referencia para ajustar los permisos de la app.",
        affected=matrix,
    ))
    return findings


# ------------------------------------------------------------------- Organización
def organization_findings(org: dict, now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    plans = org.get("assignedPlans") or []

    premium = sorted({ENTRA_PREMIUM_PLANS[p["servicePlanId"]] for p in plans
                      if p.get("servicePlanId") in ENTRA_PREMIUM_PLANS and p.get("capabilityStatus") == "Enabled"})
    if not premium:
        findings.append(Finding(
            id="ORG-001", category="Organización", severity=Severity.MEDIUM,
            title="El tenant no tiene Entra ID P1 ni P2",
            description=("Sin P1 no hay acceso condicional (MFA solo vía security defaults), ni informes de registro "
                         "de MFA, ni último inicio de sesión de usuarios, ni Identity Protection: muchas comprobaciones "
                         "de seguridad no son posibles."),
            recommendation="Valorar Entra ID P1 (incluido en Microsoft 365 Business Premium) o, como mínimo, verificar que los security defaults están activos.",
            affected=[f"{p.get('service')} ({p.get('capabilityStatus')})" for p in plans],
        ))

    if not org.get("securityComplianceNotificationMails"):
        findings.append(Finding(
            id="ORG-002", category="Organización", severity=Severity.LOW,
            title="Sin contacto de notificaciones de seguridad y cumplimiento",
            description="Microsoft no tiene a quién avisar de incidentes de seguridad o cumplimiento que afecten al tenant.",
            recommendation="Configurar un buzón de seguridad (no personal) en las propiedades del tenant.",
        ))
    if not org.get("technicalNotificationMails"):
        findings.append(Finding(
            id="ORG-003", category="Organización", severity=Severity.LOW,
            title="Sin contacto técnico de notificaciones",
            description="Los avisos técnicos del servicio no llegan a nadie.",
            recommendation="Configurar un buzón técnico compartido.",
        ))
    if not (org.get("privacyProfile") or {}).get("contactEmail"):
        findings.append(Finding(
            id="ORG-004", category="Organización", severity=Severity.LOW,
            title="Sin contacto de privacidad configurado",
            description="Los usuarios externos (invitados) no ven a quién dirigirse por temas de privacidad (RGPD).",
            recommendation="Configurar el contacto y la URL de la declaración de privacidad en las propiedades del tenant.",
        ))

    domains = org.get("verifiedDomains") or []
    if domains and all(d.get("name", "").endswith(".onmicrosoft.com") for d in domains):
        findings.append(Finding(
            id="ORG-005", category="Organización", severity=Severity.INFO,
            title="Solo existe el dominio inicial *.onmicrosoft.com",
            description="Las cuentas usan el dominio técnico de Microsoft; no hay dominio corporativo verificado.",
            recommendation="Si el tenant es productivo, verificar el dominio corporativo y configurar SPF/DKIM/DMARC.",
            affected=[d["name"] for d in domains],
        ))

    if org.get("onPremisesSyncEnabled"):
        last = parse_graph_datetime(org.get("onPremisesLastSyncDateTime"))
        if not last or now - last > timedelta(days=3):
            findings.append(Finding(
                id="ORG-006", category="Organización", severity=Severity.HIGH,
                title="La sincronización con el Active Directory local está parada",
                description="Bajas o cambios de contraseña en el AD local no llegan a la nube: ex-empleados conservan acceso.",
                recommendation="Revisar el servidor de Entra Connect / Cloud Sync.",
                affected=[f"Última sincronización: {last:%Y-%m-%d}" if last else "Nunca"],
            ))

    quota = org.get("directorySizeQuota") or {}
    if quota.get("total") and quota.get("used", 0) / quota["total"] > 0.8:
        findings.append(Finding(
            id="ORG-007", category="Organización", severity=Severity.MEDIUM,
            title="Cuota de objetos del directorio por encima del 80 %",
            description="Al llegar al límite no se podrán crear usuarios, grupos ni aplicaciones.",
            recommendation="Limpiar objetos obsoletos o solicitar ampliación de cuota.",
            affected=[f"{quota['used']} / {quota['total']}"],
        ))
    return findings


# --------------------------------------------------------- Registros de aplicaciones
def _credentials(app: dict) -> list[tuple[str, dict]]:
    return ([("secreto", c) for c in app.get("passwordCredentials") or []]
            + [("certificado", c) for c in app.get("keyCredentials") or []])


def _redirect_uris(obj: dict) -> list[str]:
    uris = list(obj.get("replyUrls") or [])
    for section in ("web", "spa", "publicClient"):
        uris += (obj.get(section) or {}).get("redirectUris") or []
    return uris


def insecure_redirects(obj: dict) -> list[str]:
    """URIs http:// que no son localhost (en localhost es normal para apps de escritorio/desarrollo)."""
    return [u for u in _redirect_uris(obj)
            if u.lower().startswith("http://") and not any(h in u.lower() for h in ("localhost", "127.0.0.1"))]


def app_registration_findings(apps: list[dict], owner_counts: dict[str, Optional[int]],
                              now: datetime, expiry_days: int = 30) -> list[Finding]:
    expiring, expired, long_lived, multi, ownerless, redirects = [], [], [], [], [], []

    for app in apps:
        name = app.get("displayName", app.get("appId"))
        active = 0
        for kind, c in _credentials(app):
            start, end = parse_graph_datetime(c.get("startDateTime")), parse_graph_datetime(c.get("endDateTime"))
            if not end:
                continue
            label = f"{name} — {kind} '{c.get('displayName') or str(c.get('keyId', ''))[:8]}'"
            if end < now:
                expired.append(f"{label} (caducó {end:%Y-%m-%d})")
                continue
            active += 1
            if end - now <= timedelta(days=expiry_days):
                expiring.append(f"{label} (caduca {end:%Y-%m-%d}, en {(end - now).days} días)")
            if kind == "secreto" and start and end - start > timedelta(days=366):
                long_lived.append(f"{label} (válido {(end - start).days // 30} meses, hasta {end:%Y-%m-%d})")
        if active > 1:
            multi.append(f"{name} ({active} credenciales activas)")
        if owner_counts.get(app.get("id")) == 0:
            ownerless.append(name)
        if insecure_redirects(app):
            redirects.append(f"{name}: {', '.join(insecure_redirects(app))}")

    findings: list[Finding] = []
    if expiring:
        findings.append(Finding(
            id="APP-001", category="Aplicaciones", severity=Severity.MEDIUM,
            title=f"{len(expiring)} credenciales de aplicación caducan en menos de {expiry_days} días",
            description="Cuando caduquen, las integraciones que las usan dejarán de funcionar.",
            recommendation="Rotar ya: crear la credencial nueva, desplegarla y borrar la antigua.",
            affected=sorted(expiring),
        ))
    if long_lived:
        findings.append(Finding(
            id="APP-002", category="Aplicaciones", severity=Severity.MEDIUM,
            title=f"{len(long_lived)} secretos de cliente con validez superior a 12 meses",
            description="Un secreto filtrado sirve hasta que caduca. Microsoft recomienda vidas cortas (≤ 6-12 meses) o certificados.",
            recommendation="Sustituir por certificados o identidades administradas; si no, secretos de ≤ 6 meses con rotación.",
            affected=sorted(long_lived),
        ))
    if ownerless:
        findings.append(Finding(
            id="APP-003", category="Aplicaciones", severity=Severity.LOW,
            title=f"{len(ownerless)} aplicaciones sin propietario",
            description="Nadie es responsable de rotar sus secretos ni de revisar sus permisos.",
            recommendation="Asignar al menos dos propietarios por aplicación.",
            affected=sorted(ownerless),
        ))
    if multi:
        findings.append(Finding(
            id="APP-004", category="Aplicaciones", severity=Severity.LOW,
            title=f"{len(multi)} aplicaciones con varias credenciales activas a la vez",
            description="Suele indicar rotaciones en las que no se borró la credencial antigua: más secretos que pueden filtrarse.",
            recommendation="Mantener una sola credencial activa (dos solo durante la rotación).",
            affected=sorted(multi),
        ))
    if redirects:
        findings.append(Finding(
            id="APP-005", category="Aplicaciones", severity=Severity.MEDIUM,
            title=f"{len(redirects)} aplicaciones con URI de redirección http:// sin cifrar",
            description="Los códigos de autorización viajan en claro y pueden interceptarse.",
            recommendation="Usar solo https:// (http:// únicamente para localhost).",
            affected=sorted(redirects),
        ))
    if expired:
        findings.append(Finding(
            id="APP-006", category="Aplicaciones", severity=Severity.LOW,
            title=f"{len(expired)} credenciales caducadas sin borrar",
            description="No funcionan, pero ensucian el inventario y ocultan qué credenciales están en uso.",
            recommendation="Eliminarlas.",
            affected=sorted(expired),
        ))
    return findings


# ------------------------------------------------------ Aplicaciones empresariales
def enterprise_app_findings(sps: list[dict], tenant_id: str, app_permissions: dict[str, list[str]],
                            delegated_grants: dict[str, list[dict]], own_app_id: str, now: datetime) -> list[Finding]:
    by_origin: dict[str, list[dict]] = {}
    for sp in sps:
        by_origin.setdefault(origin(sp, tenant_id), []).append(sp)
    third = by_origin.get("tercero", [])
    findings: list[Finding] = []

    recent = [f"{sp.get('displayName')} [{origin(sp, tenant_id)}] ({created:%Y-%m-%d})"
              for sp in sps if origin(sp, tenant_id) != "microsoft"
              and (created := parse_graph_datetime(sp.get("createdDateTime"))) and now - created <= timedelta(days=30)]
    if recent:
        findings.append(Finding(
            id="ENT-005", category="Aplicaciones", severity=Severity.INFO,
            title=f"{len(recent)} aplicaciones añadidas en los últimos 30 días",
            description="Las apps nuevas son el primer sitio donde mirar ante un posible consent phishing.",
            recommendation="Confirmar que cada una se añadió a propósito.",
            affected=sorted(recent),
        ))

    inventory = [f"{sp.get('displayName')} [{origin(sp, tenant_id)}]" for sp in sps if origin(sp, tenant_id) != "microsoft"]
    findings.append(Finding(
        id="ENT-006", category="Aplicaciones", severity=Severity.INFO,
        title=f"Inventario: {len(sps)} aplicaciones empresariales ({len(by_origin.get('microsoft', []))} de Microsoft, "
              f"{len(by_origin.get('propia', []))} propias, {len(third)} de terceros)",
        description="Aplicaciones que no son de Microsoft con presencia en el tenant.",
        recommendation="Revisar periódicamente y eliminar las que no se usen.",
        affected=sorted(inventory),
    ))
    return findings


# ------------------------------------------------------------------------ Gobierno
def governance_findings(admin_units: Optional[list], access_reviews: Optional[list]) -> list[Finding]:
    findings: list[Finding] = []
    if access_reviews == []:
        findings.append(Finding(
            id="GOV-001", category="Gobierno", severity=Severity.LOW,
            title="No hay revisiones de acceso configuradas",
            description="Nadie revisa periódicamente si invitados, miembros de grupos o administradores siguen necesitando su acceso.",
            recommendation="Configurar Access Reviews trimestrales para invitados y roles privilegiados (requiere Entra ID P2 / Governance).",
        ))
    if admin_units == []:
        findings.append(Finding(
            id="GOV-002", category="Gobierno", severity=Severity.INFO,
            title="No hay unidades administrativas",
            description="Toda la administración delegada es a nivel de tenant completo. Normal en organizaciones pequeñas.",
            recommendation="Si hay varias sedes o departamentos con administradores propios, usar unidades administrativas.",
        ))
    return findings
