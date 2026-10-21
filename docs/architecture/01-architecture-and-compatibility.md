# 01 — Architettura e compatibilità

Documento di riferimento tecnico (Fase 1). La sintesi decisionale è nel doc di
progetto `claude/architettura-e-compatibilita.md`.

## 1. Scelta della base: Debian stabile + strumenti Kali (pinning)

**Decisione:** base **Debian 13 (trixie) stabile**, con repository **Kali** aggiunto
e tenuto a priorità bassa tramite APT pinning. Gli strumenti vengono dalla
selezione Kali; il sistema operativo di base, con il suo ciclo di sicurezza,
resta Debian.

Motivazioni:

| Criterio | Debian stabile | Perché conta |
|---|---|---|
| Stabilità | Release congelate, regressioni rare | Un sistema forense/IR non deve rompersi a metà indagine |
| Aggiornamenti di sicurezza | Debian Security Team + LTS | Catena di fiducia matura e verificabile |
| Compatibilità pacchetti | Il più ampio ecosistema `.deb` | Kali stesso deriva da Debian testing/sid |
| Supporto hardware | Kernel Debian + `firmware-*` non-free | Wi-Fi/GPU moderni funzionano con firmware dichiarati |
| Manutenzione | Processi noti, documentazione enorme | Riproducibilità e bus-factor |
| Riproducibilità | `live-build` ufficiale Debian | Build deterministica e auditabile |

**Perché non partire da Kali puro:** Kali è rolling (segue sid) → maggiore
superficie di regressione, meno adatto come SO *stabile* per forense dove conta
la ripetibilità. Prendiamo gli **strumenti** di Kali senza ereditarne il modello
rolling sull'intero sistema.

### APT pinning (vedi `build/config/includes.chroot/etc/apt/preferences.d/`)

- Debian: priorità **990** (default, vince sempre a parità)
- Kali: priorità **100** (installabile esplicitamente, non aggiorna in massa il sistema)

Questo evita che un `apt upgrade` trascini mezza Kali rolling dentro un sistema
Debian stabile, pur permettendo `apt install <tool-kali>`.

## 2. Architettura hardware

- Target primario: **x86-64 / amd64** (Intel e AMD).
- Nessuna promessa di compatibilità universale. Matrice in `docs/maintainer/compatibility-matrix.md`.
- Apple Silicon (ARM64): **non** boot USB nativo (vincolo iBoot). Solo VM o
  installazione assistita stile Asahi, immagine separata, fuori dallo scope alpha.

### Firmware & boot

- **UEFI**: GRUB EFI (`grubx64.efi`) + bootloader.
- **BIOS legacy**: GRUB PC (`i386-pc`) con isohybrid → stessa ISO avviabile in
  entrambe le modalità (`grub-mkrescue`/`live-build` gestiscono l'ibrido).
- **Secure Boot**: al primo rilascio alpha **non** firmato con chiave Microsoft.
  Documentato: l'utente disabilita Secure Boot *oppure* usa shim+MOK enrollment
  (roadmap Fase 7). Non dichiariamo Secure Boot "supportato" finché non testato.
- **USB**: isohybrid scrivibile con `dd`/Etcher su chiavetta. USB 3.x consigliato;
  USB 2.0 funziona ma lento (documentato).

## 3. Modello Live + persistenza

- **Live** (`live-boot`): root su squashfs in sola lettura + overlay tmpfs in RAM.
  Nessuna scrittura sul disco interno. All'arresto, l'overlay RAM si perde.
- **Persistenza opzionale** (`live-boot` persistence): partizione/file LUKS2
  etichettata `persistence` con `persistence.conf`. Cifrata, sbloccata con
  passphrase all'avvio. Non distruttiva: convive con la partizione live della
  stessa chiavetta. Vedi `privacy/` e gli script in `build/config/includes.chroot`.
- **Toram** opzionale: copia la squashfs in RAM per poter rimuovere la chiavetta.

## 4. Desktop

- **KDE Plasma** (Wayland con fallback X11). Scelto perché: altamente
  tematizzabile senza forkare, componenti mantenuti, HiDPI/scaling solidi,
  accessibilità integrata, due temi (chiaro/scuro) nativi.
- Look-and-feel macOS-inspired ottenuto con **configurazione** (Plasma panel
  superiore per global menu/stato + Latte-style dock o plasma panel inferiore),
  **non** riscrivendo un DE da zero. Niente asset Apple: icone e font con licenza
  libera (es. icon theme libero, font famiglia Inter/Noto). Dettaglio in `desktop/`.
- Launcher centrale: KRunner (ricerca universale: app, file, guide, azioni).

## 5. Security Center (architettura software)

- **Linguaggio:** Python 3.11+.
- **Separazione netta core/GUI:**
  - `core/` — logica headless, nessuna dipendenza GUI. Testabile e usabile da CLI.
    Modello del catalogo strumenti, rilevamento capacità, gating autorizzazioni,
    esecuzione comandi, parsing output, gestione progetti/report.
  - `gui/` — PySide6 (Qt6). Solo presentazione; chiama il core.
- **Tre modalità** (Beginner/Professional/Expert) implementate come *livelli di
  esposizione* sullo stesso motore: la modalità cambia cosa si vede e quali
  default, **mai** i risultati silenziosamente.
- **Privilegi:** il core gira non privilegiato; le azioni privilegiate passano da
  `pkexec`/polkit con richiesta esplicita. Nessun demone di rete in ascolto di
  default.

## 6. Privacy

- **Tor Browser ufficiale** (non ri-pacchettizzato in modo da alterarne il
  fingerprinting). Scaricato/verificato in fase di build dal Tor Project.
- Tre profili: Standard / Tor Anonymity / Hardened.
- **Kill-switch nftables fail-closed** (`privacy/nftables/`): in modalità Tor,
  tutto il traffico non-Tor è bloccato; niente fallback diretto silenzioso.
- Test DNS-leak e verifica percorso in `privacy/tests/`.
- Limiti dell'anonimato dichiarati esplicitamente (vedi `docs/.../privacy`).

## 7. Sicurezza di sistema

- Minimo privilegio, polkit per azioni privilegiate, firewall documentato,
  update firmati (APT + chiavi), persistenza cifrata, telemetria non essenziale
  disattivata, nessun accesso remoto attivo di default, SBOM + scansione
  dipendenze in CI.

## 8. Rischi e dipendenze principali (Fase 1)

| Rischio | Impatto | Mitigazione |
|---|---|---|
| Mirror Debian/Kali non raggiungibili in build | Build fallisce | Mirror configurabile, cache apt, build offline documentata |
| Redistribuzione Tor Browser/Burp/Ghidra | Vincoli di licenza | Tor/Ghidra/ZAP redistribuibili; Burp Community → installazione opzionale guidata, non inclusa nella ISO |
| Secure Boot | Non boota su alcune macchine | Documentato; roadmap shim/MOK |
| Driver Wi-Fi monitor mode | Funzioni wireless non garantite | Rilevamento capacità a runtime; niente promesse |
| Firmware non-free | Alcuni preferiscono blob-free | Immagine include `firmware-*`; variante blob-free come roadmap |
