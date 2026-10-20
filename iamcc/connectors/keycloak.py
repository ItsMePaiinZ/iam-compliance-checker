"""Connector für Keycloak über die Admin-REST-API.

Holt Nutzer, Service-Accounts, MFA-Status, Rollen, letzte Logins und
Realm-Einstellungen und übersetzt sie in das neutrale Modell aus `iamcc.model`.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import requests

from iamcc.model import Identity, PasswordPolicy, Snapshot, TenantSettings

MFA_CREDENTIAL_TYPES = {"otp", "webauthn", "webauthn-passwordless"}

# Rollen, die ein Konto als privilegiert markieren. Anpassbar pro Umgebung.
DEFAULT_PRIVILEGED_REALM_ROLES = {"admin"}
DEFAULT_PRIVILEGED_CLIENT_ROLES = {
    "realm-management": {
        "realm-admin",
        "manage-users",
        "manage-realm",
        "manage-clients",
        "manage-authorization",
        "impersonation",
    }
}

PAGE_SIZE = 100


def _from_millis(value: int | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc)


def parse_password_policy(raw: str | None) -> PasswordPolicy:
    """Zerlegt z. B. 'length(12) and digits(1) and notUsername(undefined)'."""
    raw = raw or ""
    parts = dict(re.findall(r"(\w+)\(([^)]*)\)", raw))

    def as_int(key: str) -> int:
        try:
            return int(parts.get(key, 0))
        except ValueError:
            return 0

    return PasswordPolicy(
        raw=raw,
        min_length=as_int("length"),
        require_digits=as_int("digits") > 0,
        require_uppercase=as_int("upperCase") > 0,
        require_special=as_int("specialChars") > 0,
        not_username="notUsername" in parts,
        history=as_int("passwordHistory"),
    )


class KeycloakConnector:
    source = "keycloak"

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        session: requests.Session | None = None,
        privileged_realm_roles: set[str] | None = None,
        privileged_client_roles: dict[str, set[str]] | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = session or requests.Session()
        self.privileged_realm_roles = privileged_realm_roles or DEFAULT_PRIVILEGED_REALM_ROLES
        self.privileged_client_roles = privileged_client_roles or DEFAULT_PRIVILEGED_CLIENT_ROLES
        self.timeout = timeout
        self._token: str | None = None

    # ------------------------------------------------------------------ HTTP

    def _login(self) -> None:
        # Client-Credentials-Flow: Der Checker meldet sich als eigener Service-Account
        # direkt im geprüften Realm an, nicht als Admin im master-Realm.
        # Welche Daten er lesen darf, steuern die view-*-Rollen dieses Service-Accounts.
        url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        response = self.session.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]

    def _get(self, path: str, params: dict | None = None):
        if self._token is None:
            self._login()
        url = f"{self.base_url}/admin/realms/{self.realm}{path}"
        response = self.session.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def _paged(self, path: str, params: dict | None = None) -> list[dict]:
        items: list[dict] = []
        first = 0
        while True:
            page = self._get(path, {**(params or {}), "first": first, "max": PAGE_SIZE})
            items.extend(page)
            if len(page) < PAGE_SIZE:
                return items
            first += PAGE_SIZE

    # --------------------------------------------------------------- Sammeln

    def _tenant_settings(self) -> TenantSettings:
        realm = self._get("")
        enabled_types = set(realm.get("enabledEventTypes") or [])
        return TenantSettings(
            name=realm.get("realm", self.realm),
            password_policy=parse_password_policy(realm.get("passwordPolicy")),
            brute_force_protection=bool(realm.get("bruteForceProtected")),
            login_events_enabled=bool(realm.get("eventsEnabled")) and "LOGIN" in enabled_types,
            login_events_retention_days=int(realm.get("eventsExpiration") or 0) // 86400,
        )

    def _last_logins(self) -> dict[str, datetime]:
        latest: dict[str, datetime] = {}
        for event in self._paged("/events", {"type": "LOGIN"}):
            user_id = event.get("userId")
            when = _from_millis(event.get("time"))
            if user_id and when and (user_id not in latest or when > latest[user_id]):
                latest[user_id] = when
        return latest

    def _service_account_users(self) -> list[dict]:
        users = []
        for client in self._paged("/clients"):
            if client.get("serviceAccountsEnabled"):
                user = self._get(f"/clients/{client['id']}/service-account-user")
                user["serviceAccountClientId"] = client["clientId"]
                users.append(user)
        return users

    def _roles(self, user_id: str) -> tuple[list[str], bool]:
        mappings = self._get(f"/users/{user_id}/role-mappings")
        roles: list[str] = []
        privileged = False

        for role in mappings.get("realmMappings", []):
            roles.append(role["name"])
            if role["name"] in self.privileged_realm_roles:
                privileged = True

        for client_id, mapping in (mappings.get("clientMappings") or {}).items():
            critical = self.privileged_client_roles.get(client_id, set())
            for role in mapping.get("mappings", []):
                roles.append(f"{client_id}:{role['name']}")
                if role["name"] in critical:
                    privileged = True

        return sorted(roles), privileged

    def _mfa_methods(self, user_id: str) -> list[str]:
        credentials = self._get(f"/users/{user_id}/credentials")
        return sorted({c["type"] for c in credentials if c.get("type") in MFA_CREDENTIAL_TYPES})

    def _to_identity(self, raw: dict, last_logins: dict[str, datetime]) -> Identity:
        user_id = raw["id"]
        roles, privileged = self._roles(user_id)
        is_service_account = bool(raw.get("serviceAccountClientId"))
        name = " ".join(filter(None, [raw.get("firstName"), raw.get("lastName")]))
        return Identity(
            id=user_id,
            username=raw["username"],
            enabled=bool(raw.get("enabled", True)),
            is_service_account=is_service_account,
            display_name=name or raw.get("serviceAccountClientId", ""),
            email=raw.get("email", ""),
            created_at=_from_millis(raw.get("createdTimestamp")),
            last_login=last_logins.get(user_id),
            mfa_methods=[] if is_service_account else self._mfa_methods(user_id),
            roles=roles,
            privileged=privileged,
            attributes=raw.get("attributes") or {},
        )

    def collect(self) -> Snapshot:
        tenant = self._tenant_settings()
        last_logins = self._last_logins() if tenant.login_events_enabled else {}
        raw_users = self._paged("/users", {"briefRepresentation": "false"})
        known = {u["id"] for u in raw_users}
        raw_users += [u for u in self._service_account_users() if u["id"] not in known]

        return Snapshot(
            source=self.source,
            collected_at=datetime.now(timezone.utc),
            tenant=tenant,
            identities=[self._to_identity(u, last_logins) for u in raw_users],
        )
