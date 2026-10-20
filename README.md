# IAM Compliance Checker

Prüft die Konfiguration eines Identity Providers automatisch auf typische IAM-Schwachstellen und ordnet die Befunde ISO 27001:2022 und NIS2 zu.

Beispiele für Befunde: Konten ohne MFA, privilegierte Konten ohne MFA, inaktive Admins, ausgeschiedene Mitarbeiter mit aktivem Konto, geteilte Konten, überprivilegierte Service-Accounts, schwache Passwortrichtlinie.

> Status: in Entwicklung. Testumgebung und Keycloak-Connector sind fertig, die Prüfungen und der Bericht folgen.

## Aufbau

```
Connector (Keycloak, später Entra ID)
        │  holt Nutzer, Rollen, MFA, Logins, Einstellungen
        ▼
Neutrales Datenmodell (Snapshot)
        │
        ▼
Prüfungen  ──►  Zuordnung zu ISO 27001 / NIS2  ──►  Bericht
```

Die Prüflogik kennt die Datenquelle nicht. Ein neuer Identity Provider braucht nur einen neuen Connector.

| Ordner | Inhalt |
|---|---|
| `testenv/` | Test-Realm der fiktiven „Muster GmbH“ mit absichtlich eingebauten Schwachstellen ([Übersicht](testenv/SCHWACHSTELLEN.md)) |
| `iamcc/model.py` | Plattformunabhängiges Datenmodell |
| `iamcc/connectors/` | Connectoren je Identity Provider |
| `iamcc/checks/` | Prüfungen (folgt) |
| `mappings/` | Zuordnung Prüfung → ISO 27001 / NIS2 (folgt) |
| `tests/` | Unit-Tests, laufen ohne Keycloak |

## Schnellstart

Voraussetzungen: Docker und Python 3.11+.

```bash
# 1. Keycloak mit Test-Realm starten
docker compose up -d
# Admin-Konsole: http://localhost:8080  (admin / admin, nur lokal)

# 2. Abhängigkeiten installieren
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# 3. Daten einsammeln
python -m iamcc collect --out reports/snapshot.json

# 4. Tests
pytest
```

Beim ersten Start braucht Keycloak etwa eine halbe Minute, bis der Realm importiert ist.

## Roadmap

- [x] Testumgebung mit Keycloak und unsicherem Test-Realm
- [x] Keycloak-Connector (Nutzer, Service-Accounts, MFA, Rollen, letzte Logins, Realm-Einstellungen)
- [ ] Prüfungen mit Schweregrad
- [ ] Zuordnung zu ISO 27001:2022 Anhang A und NIS2
- [ ] Bericht als Markdown/HTML, Fehlercode bei kritischen Befunden
- [ ] GitHub Action, die den Checker gegen einen Keycloak-Container laufen lässt
- [ ] Entra-ID-Connector über Microsoft Graph

## Hinweise

- Die „Muster GmbH“ und alle Konten sind frei erfunden. Passwörter und Secrets im Test-Realm sind Testwerte für die lokale Umgebung.
- Die Zuordnung zu ISO 27001 und NIS2 ist eine eigene Interpretation und keine Rechts- oder Zertifizierungsberatung.
- Keinen Normtext ins Repository aufnehmen, nur Control-Nummern und eigene Beschreibungen.
