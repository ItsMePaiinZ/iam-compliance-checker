# Eingebaute Schwachstellen im Test-Realm „Muster GmbH“

Die Firma ist frei erfunden. Alle Namen, E-Mail-Adressen und Passwörter sind Testwerte für die lokale Umgebung.

Der Realm enthält absichtlich Fehler, die der Checker finden soll:

| Konto / Einstellung | Schwachstelle | Erwarteter Befund |
|---|---|---|
| Realm-Passwortrichtlinie | Nur `length(6)`, keine weiteren Anforderungen | Schwache Passwortrichtlinie |
| Realm-Einstellung | Brute-Force-Schutz deaktiviert | Kein Schutz gegen Passwort-Raten |
| `t.schmidt` | Admin ohne MFA | Privilegiertes Konto ohne MFA (kritisch) |
| `l.fischer` | Kein MFA | Konto ohne MFA |
| `k.alt` | Admin, Konto seit Januar 2025, keine Login-Events | Inaktives privilegiertes Konto |
| `j.becker` | Ausgeschieden (30.06.2026), Konto noch aktiv | Offboarding nicht durchgeführt (kritisch) |
| `empfang` | Geteiltes Konto, Passwort = Benutzername, HR-Rolle | Nicht personengebundenes Konto mit unnötigen Rechten |
| `reporting-tool` | Service-Account mit `realm-admin` | Überprivilegierte technische Identität |

Kontrollfälle, die **keinen** Befund erzeugen dürfen:

| Konto | Warum korrekt |
|---|---|
| `m.mueller` | Admin mit MFA, aktiv genutzt |
| `s.weber`, `p.wagner`, `a.hoffmann` | Normale Konten mit MFA |
| `f.koch` | Ausgeschieden und korrekt deaktiviert |

Hinweis zu `k.alt`: Keycloak speichert letzte Logins nicht direkt am Nutzer. Der Checker leitet Inaktivität aus den Login-Events ab (im Realm aktiviert, 90 Tage Aufbewahrung). Ein Konto, das älter als 90 Tage ist und in diesem Zeitraum kein Login-Event hat, gilt als inaktiv.
