"""Kommandozeile.

Aktuell (Schritt 3): Daten aus Keycloak einsammeln und als Snapshot speichern.
    python -m iamcc collect --out reports/snapshot.json

Die Prüfungen (Schritt 4) und der Bericht (Schritt 5) kommen später dazu.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from iamcc.connectors.keycloak import KeycloakConnector


def cmd_collect(args: argparse.Namespace) -> int:
    connector = KeycloakConnector(
        base_url=args.url,
        realm=args.realm,
        admin_user=os.environ.get("KC_ADMIN_USER", "admin"),
        admin_password=os.environ.get("KC_ADMIN_PASSWORD", "admin"),
    )
    snapshot = connector.collect()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    identities = snapshot.identities
    print(f"Quelle:       {snapshot.source} / {snapshot.tenant.name}")
    print(f"Identitäten:  {len(identities)} (davon {sum(i.is_service_account for i in identities)} Service-Accounts)")
    print(f"Ohne MFA:     {sum(1 for i in identities if not i.is_service_account and not i.has_mfa)}")
    print(f"Privilegiert: {sum(i.privileged for i in identities)}")
    print(f"Gespeichert:  {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iamcc", description="IAM Compliance Checker")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="Daten aus Keycloak einsammeln")
    collect.add_argument("--url", default=os.environ.get("KC_URL", "http://localhost:8080"))
    collect.add_argument("--realm", default=os.environ.get("KC_REALM", "muster-gmbh"))
    collect.add_argument("--out", default="reports/snapshot.json")
    collect.set_defaults(func=cmd_collect)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
