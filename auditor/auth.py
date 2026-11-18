"""Obtención del token de acceso (flujo client credentials, app-only)."""
import msal

from .config import Config

GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

# Errores habituales al configurar la app y qué revisar en cada caso
AADSTS_HINTS = {
    "AADSTS90002": "El TENANT_ID no existe. Usa el 'Directory (tenant) ID' de la pantalla Overview de la app "
                   "(no el Object ID ni el Subscription ID), o el dominio: midominio.onmicrosoft.com",
    "AADSTS700016": "El CLIENT_ID no existe en ese tenant. Usa el 'Application (client) ID' de la app.",
    "AADSTS7000215": "CLIENT_SECRET inválido. Copia la columna 'Value' del secreto (no el 'Secret ID'); "
                     "solo se muestra al crearlo, si no lo tienes crea uno nuevo.",
    "AADSTS7000222": "El CLIENT_SECRET ha caducado. Crea uno nuevo en Certificates & secrets.",
}


class AuthError(Exception):
    pass


def token_claims(token: str) -> dict:
    """Decodifica (sin validar firma) el payload del JWT: sirve para ver los permisos (claim 'roles')."""
    import base64
    import json
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _hint(text: str) -> str:
    for code, hint in AADSTS_HINTS.items():
        if code in text:
            return f"\n  -> {hint}"
    return ""


def get_token(config: Config) -> str:
    try:
        app = msal.ConfidentialClientApplication(
            client_id=config.client_id,
            authority=f"https://login.microsoftonline.com/{config.tenant_id}",
            client_credential=config.client_secret,
        )
    except ValueError as e:  # MSAL valida el tenant al construir el cliente
        detail = f"{e} {e.__context__ or ''}"  # el código AADSTS viene en la excepción encadenada
        raise AuthError(f"No se pudo validar el tenant.{_hint(detail) or ' ' + str(e)[:300]}") from None

    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in result:
        desc = result.get("error_description", "")
        raise AuthError(f"No se pudo obtener el token: {result.get('error')}{_hint(desc) or ' - ' + desc[:300]}")
    return result["access_token"]
