"""Cliente minimo de Microsoft Graph: paginacion, reintentos ante throttling y errores claros."""
import time
from typing import Any, Iterator, Optional

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphError(Exception):
    def __init__(self, status: int, message: str, url: str, code: str = ""):
        super().__init__(f"[{status}] {message} ({url})")
        self.status = status
        self.url = url
        self.code = code
        self.message = message


class GraphPermissionError(GraphError):
    """403: falta un permiso de la app o una licencia (p. ej. Entra ID P1/P2)."""


class GraphClient:
    def __init__(self, token: str, base_url: str = GRAPH_BASE, max_retries: int = 5):
        self.base_url = base_url
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"

    def get(self, path: str, params: Optional[dict] = None,
            headers: Optional[dict] = None) -> dict[str, Any]:
        url = self._url(path)
        for attempt in range(self.max_retries + 1):
            resp = self.session.get(url, params=params, headers=headers, timeout=60)

            # Throttling o error transitorio: esperar y reintentar
            if resp.status_code in (429, 503, 504) and attempt < self.max_retries:
                wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(wait)
                continue

            if resp.ok:
                return resp.json()

            code, message = self._error_details(resp)
            if resp.status_code == 403:
                raise GraphPermissionError(resp.status_code, message, url, code)
            raise GraphError(resp.status_code, message, url, code)

        raise GraphError(429, "Demasiados reintentos", url)

    def get_all(self, path: str, params: Optional[dict] = None,
                headers: Optional[dict] = None) -> Iterator[dict[str, Any]]:
        """Itera todos los elementos de una coleccion siguiendo @odata.nextLink."""
        data = self.get(path, params=params, headers=headers)
        yield from data.get("value", [])
        while next_link := data.get("@odata.nextLink"):
            # nextLink ya incluye los parametros de la consulta
            data = self.get(next_link, headers=headers)
            yield from data.get("value", [])

    @staticmethod
    def _error_details(resp: requests.Response) -> tuple[str, str]:
        """(código, mensaje) del error de Graph."""
        try:
            error = resp.json()["error"]
            return error.get("code", ""), error.get("message", "")
        except (ValueError, KeyError, TypeError, AttributeError):
            return "", resp.text[:300]
