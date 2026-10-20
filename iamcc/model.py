"""Plattformunabhängiges Datenmodell.

Jeder Connector (Keycloak, später Entra ID) liefert einen `Snapshot`.
Die Prüfungen arbeiten nur mit diesem Modell und kennen die Quelle nicht.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class Identity:
    id: str
    username: str
    enabled: bool
    is_service_account: bool = False
    display_name: str = ""
    email: str = ""
    created_at: datetime | None = None
    last_login: datetime | None = None
    mfa_methods: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    privileged: bool = False
    attributes: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_mfa(self) -> bool:
        return bool(self.mfa_methods)


@dataclass
class PasswordPolicy:
    raw: str = ""
    min_length: int = 0
    require_digits: bool = False
    require_uppercase: bool = False
    require_special: bool = False
    not_username: bool = False
    history: int = 0


@dataclass
class TenantSettings:
    name: str
    password_policy: PasswordPolicy
    brute_force_protection: bool = False
    login_events_enabled: bool = False
    login_events_retention_days: int = 0


@dataclass
class Snapshot:
    source: str
    collected_at: datetime
    tenant: TenantSettings
    identities: list[Identity]

    def to_dict(self) -> dict:
        def convert(value):
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, dict):
                return {k: convert(v) for k, v in value.items()}
            if isinstance(value, list):
                return [convert(v) for v in value]
            return value

        return convert(asdict(self))
