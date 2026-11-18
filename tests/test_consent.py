"""Tests del detector de concesiones fraudulentas."""
from datetime import datetime, timedelta, timezone

from auditor.models import Severity
from auditor.rules.consent import consent_findings, score_app

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
MS = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
TENANT = "t"


def sp(id_, name, owner="otro", days_old=400, verified=False, **extra):
    return {"id": id_, "appId": f"app-{id_}", "displayName": name, "appOwnerOrganizationId": owner,
            "createdDateTime": (NOW - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verifiedPublisher": {"verifiedPublisherId": "123"} if verified else {}, **extra}


def test_classic_consent_phishing_is_critical():
    # Tercero sin verificar, nombre que imita a Microsoft, nuevo, lee el correo de un usuario con acceso persistente
    app = sp("1", "Office 365 Mail Sync", days_old=3)
    grants = [{"consentType": "Principal", "principalId": "u1", "scope": "openid Mail.Read offline_access"}]
    findings = consent_findings([app], TENANT, {}, {"1": grants}, own_app_id="x", now=NOW)
    assert findings[0].severity is Severity.CRITICAL
    score, _ = score_app(app, TENANT, [], grants, NOW)
    assert score == 1 + 2 + 3 + 2 + 1 + 1  # tercero, no verificado, imita, delegado, offline, nueva


def test_verified_third_party_with_basic_scopes_is_not_reported():
    app = sp("2", "Zoom", verified=True)
    grants = [{"consentType": "AllPrincipals", "scope": "openid profile User.Read"}]
    assert consent_findings([app], TENANT, {}, {"2": grants}, own_app_id="x", now=NOW) == []


def test_microsoft_apps_are_ignored_and_own_tool_excluded():
    ms = sp("3", "Microsoft Teams", owner=MS)
    own = sp("4", "Auditor", owner=TENANT)
    perms = {"3": ["Microsoft Graph: Directory.ReadWrite.All"], "4": ["Microsoft Graph: AgentIdUser.ReadWrite.All"]}
    assert consent_findings([ms, own], TENANT, perms, {}, own_app_id="app-4", now=NOW) == []


def test_own_app_with_high_impact_permissions_is_medium():
    app = sp("5", "Conector RRHH", owner=TENANT)
    findings = consent_findings([app], TENANT, {"5": ["Microsoft Graph: User.ReadWrite.All"]}, {}, own_app_id="x", now=NOW)
    assert findings[0].severity is Severity.MEDIUM  # +3: legítima hasta que se demuestre lo contrario


def test_credentials_on_microsoft_app_is_backdoor():
    ms = sp("6", "Office 365 Exchange Online", owner=MS, passwordCredentials=[{"keyId": "k"}])
    findings = consent_findings([ms], TENANT, {}, {}, own_app_id="x", now=NOW)
    assert [f.id for f in findings] == ["CON-MS1"] and findings[0].severity is Severity.HIGH


def test_org_wide_consent_adds_points():
    app = sp("7", "Herramienta CRM", verified=True)
    user_grant = [{"consentType": "Principal", "principalId": "u", "scope": "Files.Read.All"}]
    org_grant = [{"consentType": "AllPrincipals", "scope": "Files.Read.All"}]
    assert score_app(app, TENANT, [], org_grant, NOW)[0] == score_app(app, TENANT, [], user_grant, NOW)[0] + 1


def test_own_app_with_microsoft_like_name_is_not_impersonation():
    app = sp("8", "M365-Audit-Dashboard", owner=TENANT, days_old=1)
    assert score_app(app, TENANT, [], [], NOW)[0] == 1  # solo "nueva"


def test_microsoft_tool_with_powerful_delegated_consent_is_medium():
    ge = sp("9", "Graph Explorer", owner="cdc5aeea-15c5-4db6-b079-fcadd2505dc2", days_old=0)
    grants = {"9": [{"consentType": "Principal", "principalId": "u", "scope": "Directory.ReadWrite.All"}]}
    findings = consent_findings([ge], TENANT, {}, grants, own_app_id="x", now=NOW)
    assert [f.id for f in findings] == ["CON-MS2"] and findings[0].severity is Severity.MEDIUM
