# Changelog

Versionen nach [Semantic Versioning](https://semver.org/lang/de/): `MAJOR.MINOR.PATCH`.
Die aktuelle Nummer steht in [`internal/version/VERSION`](internal/version/VERSION) und wird in Server, Crawler und Weboberfläche angezeigt.

**Bei jeder Änderung:** Eintrag hier oben ergänzen und die Nummer in `internal/version/VERSION` hochzählen –
neue Funktion → MINOR (0.6.0 → 0.7.0), Fehlerbehebung → PATCH (0.6.0 → 0.6.1).
Solange die Version mit 0 beginnt, kann sich die API noch ändern.

Die Versionen bis 0.5.0 wurden nachträglich aus den gemergten Pull Requests zusammengestellt.

## 0.8.0 – 2026-11-17

- Netze bearbeiten: „Bearbeiten“ unter „Netze & Crawler“ öffnet ein Panel mit allen Einstellungen
  (Name, Bereich, Ausnahmen, Intervalle, Ports, Offline-Schwellen, aktiv). Inventar und Verlauf bleiben erhalten;
  der Crawler muss nichts neu holen, die Änderung gilt ab dem nächsten geplanten Scan (OwnDo #187).
- Portscan-Intervall in Minuten, mindestens 15 Minuten (bisher mindestens 1 Stunde).
  API: neues Feld `portscan_interval_minutes`, `portscan_interval_hours` bleibt gültig; `scan_preset` in der Netz-Ansicht.
- Kommandozeile: `network update --id N …` ändert nur die angegebenen Einstellungen.

## 0.7.0 – 2026-11-17

- Inventar: Host-Details öffnen als Panel von rechts über der Liste statt ganz unten auf der Seite –
  auch bei langen Listen dort, wo man gerade ist. Schließen mit Esc, „Schließen“ oder Klick daneben;
  auf dem Handy bildschirmfüllend. Zeilen sind per Tastatur erreichbar (Tab, Enter).

## 0.6.1 – 2026-11-17

- `deploy/.env.example` setzte `NETCRAWL_VERSION=dev` und überdeckte damit die echte Versionsnummer.
  Wer `deploy/.env` daraus kopiert hat: die Zeile `NETCRAWL_VERSION=dev` dort entfernen.

## 0.6.0 – 2026-11-17

- Neues Design der Weboberfläche: Menü links (auf dem Handy oben), neue Seite **Übersicht** mit Kennzahlen,
  neuesten Ereignissen, Netzwerk-Status und Crawler-Status; „Netze & Crawler“ und „Administration“ zusammengefasst.
- Dunkles Design als Standard, Umschalter auf hell (merkt sich der Browser).
- Auf sehr breiten Bildschirmen bleibt die Oberfläche 1760 px breit und zentriert.
- Versionsnummer unten im Menü; feste Versionszählung mit `internal/version/VERSION` und diesem Changelog.

## 0.5.0 – 2026-11-17

- Host-Details im Inventar und eigene Hostnamen (#18).
- Neu gefundene Hosts werden sofort per Portscan geprüft (#17).

## 0.4.0 – 2026-11-15

- Crawler-Freigabe in der Oberfläche ändern, alte Installationen ersetzen, Server-Adresse einstellen (#16).
- Benachrichtigungen per Discord-Webhook (#15).
- Crawler-Installation per Einzeiler mit Einmal-Codes (#14).

## 0.3.0 – 2026-11-15

- Netze mit Zeitplan, Inventar und Änderungsmeldungen (#12, #13).

## 0.2.0 – 2026-11-15

- Zentraler Server mit PostgreSQL und Crawler-Agent (#9, #10).
- Weboberfläche zum Anmelden und lokale Testumgebung (#11).

## 0.1.0 – 2026-09-05

- Eigenständiger TCP-Connect-Scanner `netcrawler` mit CSV-/Markdown-Export.
- Service-Erkennung (TLS, HTTP-Titel, Banner, SSH-Host-Key) (#3, #4), Fehlerbehebungen (#1, #5, #6).
