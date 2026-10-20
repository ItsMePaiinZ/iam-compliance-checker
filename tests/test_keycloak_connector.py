"""Testet den Keycloak-Connector ohne laufendes Keycloak.

Eine Fake-Session beantwortet die Admin-API-Aufrufe aus dem Test-Realm
(testenv/realm-muster-gmbh.json), so wie Keycloak es nach dem Import täte.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from iamcc.connectors.keycloak import KeycloakConnector, parse_password_policy

REALM_FILE = Path(__file__).parent.parent / "testenv" / "realm-muster-gmbh.json"
BASE = "http://kc.test"
NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


class FakeKeycloak:
    """Minimaler Ersatz für requests.Session auf Basis der Realm-Exportdatei."""

    def __init__(self, realm: dict, login_events: list[dict]):
        self.realm = realm
        self.events = login_events
        self.users = []
        self.service_accounts = {}
        for u in realm["users"]:
            user = {**u, "id": f"id-{u['username']}"}
            user.setdefault("createdTimestamp", int((NOW - timedelta(days=20)).timestamp() * 1000))
            if u.get("serviceAccountClientId"):
                self.service_accounts[u["serviceAccountClientId"]] = user
            else:
                self.users.append(user)
        self.by_id = {u["id"]: u for u in self.users + list(self.service_accounts.values())}

    def post(self, url, data, timeout):
        assert url.endswith("/realms/master/protocol/openid-connect/token")
        return FakeResponse({"access_token": "fake-token"})

    def get(self, url, params=None, headers=None, timeout=None):
        assert headers["Authorization"] == "Bearer fake-token"
        path = url.split("/admin/realms/muster-gmbh", 1)[1]
        params = params or {}
        first, maximum = params.get("first", 0), params.get("max", 100)

        if path == "":
            return FakeResponse({k: v for k, v in self.realm.items() if k != "users"})
        if path == "/users":
            return FakeResponse(self.users[first : first + maximum])
        if path == "/events":
            return FakeResponse(self.events[first : first + maximum])
        if path == "/clients":
            clients = [{**c, "id": f"cid-{c['clientId']}"} for c in self.realm["clients"]]
            return FakeResponse(clients[first : first + maximum])
        if path.startswith("/clients/") and path.endswith("/service-account-user"):
            client_id = path.split("/")[2].removeprefix("cid-")
            sa = self.service_accounts[client_id]
            return FakeResponse({k: v for k, v in sa.items() if k != "serviceAccountClientId"})

        _, _, user_id, resource = path.split("/", 3)
        user = self.by_id[user_id]
        if resource == "credentials":
            return FakeResponse([{"type": c["type"]} for c in user.get("credentials", [])])
        if resource == "role-mappings":
            return FakeResponse(
                {
                    "realmMappings": [{"name": r} for r in user.get("realmRoles", [])],
                    "clientMappings": {
                        client: {"mappings": [{"name": r} for r in roles]}
                        for client, roles in (user.get("clientRoles") or {}).items()
                    },
                }
            )
        raise AssertionError(f"Unerwarteter Aufruf: {path}")


def login_events() -> list[dict]:
    recent = int((NOW - timedelta(days=2)).timestamp() * 1000)
    active = ["m.mueller", "t.schmidt", "s.weber", "j.becker", "empfang", "l.fischer", "p.wagner", "a.hoffmann"]
    return [{"type": "LOGIN", "userId": f"id-{name}", "time": recent} for name in active]


@pytest.fixture(scope="module")
def snapshot():
    realm = json.loads(REALM_FILE.read_text(encoding="utf-8"))
    connector = KeycloakConnector(BASE, "muster-gmbh", "admin", "admin", session=FakeKeycloak(realm, login_events()))
    return connector.collect()


def by_name(snapshot, username):
    return next(i for i in snapshot.identities if i.username == username)


def test_all_identities_collected_including_service_account(snapshot):
    assert len(snapshot.identities) == 11
    sa = by_name(snapshot, "service-account-reporting-tool")
    assert sa.is_service_account
    assert sa.display_name == "reporting-tool"


def test_mfa_status(snapshot):
    assert by_name(snapshot, "m.mueller").mfa_methods == ["otp"]
    assert not by_name(snapshot, "t.schmidt").has_mfa
    assert not by_name(snapshot, "l.fischer").has_mfa


def test_privileged_detection(snapshot):
    privileged = {i.username for i in snapshot.identities if i.privileged}
    assert privileged == {"m.mueller", "t.schmidt", "k.alt", "service-account-reporting-tool"}


def test_last_login_from_events(snapshot):
    assert by_name(snapshot, "m.mueller").last_login is not None
    assert by_name(snapshot, "k.alt").last_login is None
    assert by_name(snapshot, "k.alt").created_at.year == 2025


def test_tenant_settings(snapshot):
    tenant = snapshot.tenant
    assert tenant.name == "muster-gmbh"
    assert tenant.password_policy.min_length == 6
    assert not tenant.brute_force_protection
    assert tenant.login_events_enabled
    assert tenant.login_events_retention_days == 90


def test_attributes_kept_for_offboarding_checks(snapshot):
    becker = by_name(snapshot, "j.becker")
    assert becker.enabled
    assert becker.attributes["beschaeftigung"] == ["ausgeschieden"]
    assert not by_name(snapshot, "f.koch").enabled


def test_snapshot_is_json_serialisable(snapshot):
    json.dumps(snapshot.to_dict())


def test_parse_password_policy():
    policy = parse_password_policy("length(12) and digits(1) and upperCase(1) and notUsername(undefined) and passwordHistory(5)")
    assert policy.min_length == 12
    assert policy.require_digits and policy.require_uppercase
    assert not policy.require_special
    assert policy.not_username
    assert policy.history == 5
    assert parse_password_policy(None).min_length == 0
