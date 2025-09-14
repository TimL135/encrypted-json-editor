# 🔐 Encrypted JSON Editor

Ein einfacher, sicherer Desktop-Editor für JSON-Daten, die mit einem Passwort verschlüsselt werden. Ideal, um sensible Konfigurationen, Notizen oder Schlüssel-Wert-Paare lokal und geschützt zu speichern.

## ✨ Funktionen

*   **Passwortschutz:** Alle Daten werden mit AES256-GCM verschlüsselt, abgeleitet von deinem Passwort mittels Argon2.
*   **Einfache Oberfläche:** Intuitive Key-Value-Bearbeitung.
*   **Suchen & Filtern:** Schnelles Finden von Einträgen.
*   **Kopieren:** Werte einfach in die Zwischenablage kopieren.
*   **Plattformübergreifend:** Läuft nativ auf Windows, macOS und Linux (dank `eframe`/`egui`).

## 🚀 Installation & Nutzung

### Für Fedora Linux

1.  **Rust & Cargo installieren:**
    ```bash
    sudo dnf install rust cargo
    ```
    (Oder über `rustup.rs` für die neueste Version.)

2.  **Projekt klonen & bauen:**
    ```bash
    git clone <URL_ZU_DEINEM_REPO> # Falls du ein Git-Repo hast
    cd encrypted-json-editor       # Oder der Name deines Projektordners
    cargo build --release
    ```

### Für andere Plattformen (Windows, macOS)

1.  **Rust & Cargo installieren:** Folge den Anweisungen auf [rustup.rs](https://rustup.rs/).
2.  **Projekt klonen & bauen:**
    ```bash
    git clone <URL_ZU_DEINEM_REPO>
    cd encrypted-json-editor
    cargo build --release
    ```
3.  **Starten:** Das Binary findest du im `target/release/` Ordner.

## ⚠️ Wichtige Hinweise

*   **Passwort:** Das Passwort wird nicht gespeichert. Es wird nur verwendet, um den Verschlüsselungsschlüssel abzuleiten. Bei jedem Start muss es erneut eingegeben werden.
*   **Datendatei:** Die verschlüsselten Daten werden in `data.enc` und der Salt in `salt.txt` im selben Verzeichnis wie die ausführbare Datei gespeichert. Lösche diese Dateien nicht, es sei denn, du möchtest alle Daten verlieren.
*   **Sicherheit:** Dies ist eine lokale Verschlüsselung. Die Sicherheit hängt von der Stärke deines Passworts ab.

## 🤝 Mitwirken

Vorschläge und Beiträge sind willkommen! Bitte öffne ein Issue oder sende einen Pull Request.

## 📄 Lizenz

Dieses Projekt ist unter der [MIT-Lizenz](LICENSE) lizenziert.