"""Carga de configuración desde variables de entorno / archivo .env."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    tenant_id: str
    client_id: str
    client_secret: str
    inactivity_days: int = 90
    max_global_admins: int = 5


def load_config() -> Config:
    load_dotenv()

    missing = [k for k in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET") if not os.getenv(k)]
    if missing:
        raise ConfigError(
            f"Faltan variables en .env: {', '.join(missing)}. "
            "Copia .env.example a .env y rellena las credenciales."
        )

    return Config(
        tenant_id=os.environ["TENANT_ID"],
        client_id=os.environ["CLIENT_ID"],
        client_secret=os.environ["CLIENT_SECRET"],
        inactivity_days=int(os.getenv("INACTIVITY_DAYS", "90")),
        max_global_admins=int(os.getenv("MAX_GLOBAL_ADMINS", "5")),
    )
