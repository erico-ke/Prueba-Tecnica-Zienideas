"""Modelos de datos de la auditoría."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Crítica"
    HIGH = "Alta"
    MEDIUM = "Media"
    LOW = "Baja"
    INFO = "Informativa"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    affected: list[str] = field(default_factory=list)


@dataclass
class SectionResult:
    """Resultado de un área auditada (MFA, inactividad, administradores...)."""
    category: str
    status: str                      # "OK" | "Hallazgos" | "No disponible"
    findings: list[Finding] = field(default_factory=list)
    note: Optional[str] = None       # limitaciones o motivo de "No disponible"


@dataclass
class RoleAssignment:
    """Asignación de rol de directorio normalizada (grupos ya expandidos a usuarios)."""
    role_id: str
    role_name: str
    principal_id: str
    principal_type: str              # "user" | "group" | "servicePrincipal" | otro
    principal_name: str
    scope: str = "/"
    via_group: Optional[str] = None


@dataclass
class TenantData:
    """Todo lo que se ha leído del tenant. Las reglas solo trabajan con esto."""
    collected_at: datetime
    users: list[dict]
    sign_in_available: bool = False
    registration_details: Optional[list[dict]] = None
    role_assignments: Optional[list[RoleAssignment]] = None
    skus: Optional[list[dict]] = None
    unavailable: dict[str, str] = field(default_factory=dict)   # área -> motivo


@dataclass
class AuditResult:
    summary: dict
    sections: list[SectionResult]
    licenses: Optional[list[dict]] = None
