"""Tests de las reglas del modo exploración."""
from datetime import datetime, timedelta, timezone

from auditor.models import Severity
from auditor.rules import exploration as rx

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
iso = lambda d: (NOW + timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
ids = lambda fs: [f.id for f in fs]


def test_own_permissions_flags_write_sensitive_and_missing():
    fs = rx.own_permission_findings(["AgentIdUser.ReadWrite.All", "AiEnterpriseInteraction.Read.All", "User.Read.All"], ["openid"])
    assert ids(fs) == ["PRM-001", "PRM-002", "PRM-003", "PRM-004", "PRM-005"]
    assert fs[0].severity is Severity.HIGH and fs[2].affected == ["Application.Read.All"]


def test_access_beyond_permission_and_unlicensed():
    probes = [
        rx.Probe("organization", "Org", ("Organization.Read.All",), 200, count=1),
        rx.Probe("identityProtection/riskyUsers", "Riesgo", ("IdentityRiskyUser.Read.All",), 403, "Forbidden", "Your tenant is not licensed for this feature."),
        rx.Probe("users", "Usuarios", ("User.Read.All",), 403, "Authorization_RequestDenied"),  # sin permiso: esperado
    ]
    fs = rx.access_findings(probes, ["IdentityRiskyUser.Read.All"])
    assert ids(fs) == ["ACC-001", "ACC-002", "ACC-004"]


def test_organization_without_premium_and_contacts():
    org = {"assignedPlans": [{"service": "exchange", "capabilityStatus": "Enabled", "servicePlanId": "x"}],
           "technicalNotificationMails": ["it@c.com"], "verifiedDomains": [{"name": "c.onmicrosoft.com"}]}
    assert ids(rx.organization_findings(org, NOW)) == ["ORG-001", "ORG-002", "ORG-004", "ORG-005"]
    org["assignedPlans"].append({"servicePlanId": "41781fb2-bc02-4b7c-bd55-b576c07bb09d", "capabilityStatus": "Enabled"})
    assert "ORG-001" not in ids(rx.organization_findings(org, NOW))


def test_app_credentials_expiring_long_lived_and_ownerless():
    apps = [{"id": "a", "displayName": "App", "passwordCredentials": [
        {"displayName": "s1", "startDateTime": iso(-400), "endDateTime": iso(12)},
        {"displayName": "s2", "startDateTime": iso(-10), "endDateTime": iso(720)},
        {"displayName": "old", "startDateTime": iso(-400), "endDateTime": iso(-5)}],
        "web": {"redirectUris": ["http://app.contoso.com/cb", "http://localhost:8080"]}}]
    fs = rx.app_registration_findings(apps, {"a": 0}, NOW)
    assert ids(fs) == ["APP-001", "APP-002", "APP-003", "APP-004", "APP-005", "APP-006"]
    assert fs[4].affected == ["App: http://app.contoso.com/cb"]  # localhost no es hallazgo


def test_governance():
    assert ids(rx.governance_findings([], [])) == ["GOV-001", "GOV-002"]
    assert rx.governance_findings(None, None) == []  # sin acceso: no se afirma nada
