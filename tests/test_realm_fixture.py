"""Stellt sicher, dass der Test-Realm die dokumentierten Schwachstellen enthält.

Wenn jemand den Realm ändert, fallen diese Tests auf, bevor die Prüfungen
ins Leere laufen.
"""

import json
from pathlib import Path

REALM = json.loads((Path(__file__).parent.parent / "testenv" / "realm-muster-gmbh.json").read_text(encoding="utf-8"))
USERS = {u["username"]: u for u in REALM["users"]}


def has_otp(user):
    return any(c["type"] == "otp" for c in user.get("credentials", []))


def test_realm_basics():
    assert REALM["realm"] == "muster-gmbh"
    assert REALM["eventsEnabled"] is True
    assert "LOGIN" in REALM["enabledEventTypes"]


def test_weak_realm_settings():
    assert REALM["passwordPolicy"] == "length(6)"
    assert REALM["bruteForceProtected"] is False


def test_admin_without_mfa_exists():
    assert "admin" in USERS["t.schmidt"]["realmRoles"]
    assert not has_otp(USERS["t.schmidt"])


def test_former_employee_still_enabled():
    assert USERS["j.becker"]["attributes"]["beschaeftigung"] == ["ausgeschieden"]
    assert USERS["j.becker"]["enabled"] is True


def test_correct_offboarding_control_case():
    assert USERS["f.koch"]["attributes"]["beschaeftigung"] == ["ausgeschieden"]
    assert USERS["f.koch"]["enabled"] is False


def test_overprivileged_service_account():
    sa = USERS["service-account-reporting-tool"]
    assert "realm-admin" in sa["clientRoles"]["realm-management"]


def test_no_unknown_top_level_note_fields():
    # Keycloak lehnt unbekannte Felder beim Import ab, Notizen gehören in SCHWACHSTELLEN.md
    for user in REALM["users"]:
        assert not any(key.startswith("_") for key in user)
