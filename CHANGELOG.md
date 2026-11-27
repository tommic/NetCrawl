# Changelog

Versionen nach [Semantic Versioning](https://semver.org/lang/de/): `MAJOR.MINOR.PATCH`.
Die aktuelle Nummer steht in [`internal/version/VERSION`](internal/version/VERSION) und wird in Server, Crawler und Weboberfläche angezeigt.

**Bei jeder Änderung:** Eintrag hier oben ergänzen und die Nummer in `internal/version/VERSION` hochzählen –
neue Funktion → MINOR (0.6.0 → 0.7.0), Fehlerbehebung → PATCH (0.6.0 → 0.6.1).
Solange die Version mit 0 beginnt, kann sich die API noch ändern.

Die Versionen bis 0.5.0 wurden nachträglich aus den gemergten Pull Requests zusammengestellt.

## 0.12.0 – 2026-11-27

- Export für KI-Agenten: das Inventar als Text (`GET /api/v1/export.txt`) – Netze, Geräte mit offenen Ports,
  Diensten und Versionen, Software-Übersicht, Änderungen der letzten 7 Tage (`days`, `network_id` wählbar).
  Ansehen und Herunterladen unter „Administration“.
- Lese-Tokens für Agenten: in der Oberfläche erzeugen (Wert wird einmal angezeigt), auflisten mit letzter Nutzung,
  löschen. Sie erlauben nur den Export, keine Admin-Funktionen (Migration 0011).

## 0.11.0 – 2026-11-27

- Crawler aktualisieren sich selbst: Der Crawler meldet seine Version, der Server antwortet mit seiner
  (`X-NetCrawl-Version`). Weicht sie ab, stößt der Crawler den neuen Updater `netcrawl-agent-update` an (root,
  systemd). Der holt den `netcrawl-agent` selbst vom Server über den gepinnten TLS-Schlüssel, prüft SHA-256 und Version
  gegen `/install/agent/latest`, tauscht ihn aus und startet den Crawler neu. Zusätzlich ein Timer alle 6 Stunden.
  Abschaltbar mit `"auto_update": false` in der `agent.json`.
- Crawler-Liste: Spalte „Version“, veraltete Crawler sind markiert.
- Einmalig: Crawler, die vor 0.11.0 installiert wurden, einmal neu installieren (danach automatisch).
  Das Deinstallations-Skript entfernt auch den Updater.

## 0.10.0 – 2026-11-27

- Dienste und Versionen: Beim Portscan erkennt der Crawler die Software hinter jedem offenen Port –
  mit `nmap -sV`, wenn nmap installiert ist, sonst über Banner, HTTP-Header und TLS (OpenSSH, nginx, Apache,
  Postfix, Exim, MySQL/MariaDB, FTP, Dovecot …). Gespeichert pro Port (Migration 0008).
- Eigener Zeitplan pro Netz: „Diensterkennung alle …“ (Standard 24 Std., mindestens 15 Min.). Der Portscan kann
  öfter laufen; nur der fällige Portscan erkennt auch die Dienste. Neue Geräte und „Portscan jetzt“ immer.
  API: `service_interval_minutes`, Kommandozeile: `--service-interval` (Migration 0009).
- Neue Seite **Dienste**: Software mit allen Versionen und Anzahl Geräte, darunter alle Dienste einzeln, mit Suche.
  Im Host-Panel steht der Dienst neben jedem Port.
- Meldungen: andere Version derselben Software → Info, andere Software auf einem Port → Warnung.
  „Port neu offen“ nennt den erkannten Dienst.
- Das Docker-Image des Crawlers basiert jetzt auf `debian:12-slim` und enthält nmap.
- Crawler: `no_service_detection: true` in der `agent.json` schaltet die Erkennung ab. Protokoll: Job-Feld `services`.
- Handy: Die Seite war breiter als der Bildschirm (Menüleiste drückte die Seite auf); jetzt scrollt nur die Menüleiste.

## 0.9.0 – 2026-11-27

- Netz-Panel überarbeitet: Einstellungen in Gruppen (Netz, Zeitplan, Ports, Meldungen, Optionen),
  jede mit kurzer Erklärung. Host-Erkennung und Portscan stehen untereinander mit eigener Einheit (Min./Std.),
  Offline-Schwellen wahlweise in Stunden oder Tagen. „Ausnehmen“ erklärt die Schreibweise.
- Ports beim Portscan: Die Auswahl zeigt, wie viele Ports sie umfasst; die Liste steht im Tooltip bzw. zum Aufklappen.
  Neu „Eigene Ports …“ mit Einzelports und Bereichen (`22, 80, 8000-8100`); `scan_ports` in der API und `--scan-ports`
  auf der Kommandozeile verstehen jetzt auch Bereiche. API: `GET /api/v1/admin/network-options` (Port-Auswahlen und Standardwerte).
- Ungespeicherte Änderungen gehen nicht mehr verloren: Klick daneben, Esc oder „Schließen“ fragen nach
  („Verwerfen“ / „Weiter bearbeiten“). Speichern und Abbrechen bleiben unten immer sichtbar.
- Neue Netze werden im selben Panel angelegt („Netz anlegen“) statt im Formular unten auf der Seite.
- „Wichtig“ neu gedacht: Wichtige Geräte haben eine eigene, kurze Schwelle –
  „Kritisch“ nach 60 Minuten Fehlen (pro Netz einstellbar, mindestens 5 Minuten) statt erst nach der Warnschwelle (7 Tage).
  Im Host-Panel per Schalter mit Erklärung setzbar. API: `offline_critical_minutes`, Kommandozeile: `--offline-critical`.
  Die Schwelle muss länger sein als die Host-Erkennung (ein einzelner verpasster Rundgang löst keinen Alarm aus);
  ohne Angabe gilt 60 Minuten, mindestens aber zwei Erkennungs-Intervalle. Bestehende Netze bekommen das beim Update automatisch.
- Meldungstexte: „seit einer Stunde“ statt „seit 1 Stunden“.

## 0.8.0 – 2026-11-17

- Netze bearbeiten: „Bearbeiten“ unter „Netze & Crawler“ öffnet ein Panel mit allen Einstellungen
  (Name, Bereich, Ausnahmen, Intervalle, Ports, Offline-Schwellen, aktiv). Inventar und Verlauf bleiben erhalten;
  der Crawler muss nichts neu holen, die Änderung gilt ab dem nächsten geplanten Scan.
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
