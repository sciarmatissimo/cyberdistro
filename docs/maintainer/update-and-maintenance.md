# Aggiornamento, manutenzione e gestione delle vulnerabilità

## Principi
- **Repository verificati** e **pacchetti firmati** (APT + chiavi Debian/Kali).
- **Integrità dei download** verificata (hash/firma).
- **Distinzione** tra aggiornamenti del *sistema base* (Debian) e degli
  *strumenti* (Kali), coerente con l'APT pinning (Debian 990, Kali 100).
- **Ripristino**: possibilità di tornare a una configurazione funzionante.

## Flusso di aggiornamento
1. **Sistema base (Debian)**: aggiornamenti di sicurezza Debian; priorità alta.
   ```bash
   sudo apt update && sudo apt upgrade        # resta su Debian stable grazie al pinning
   ```
2. **Strumenti (Kali)**: espliciti, mai in massa.
   ```bash
   sudo apt install -t kali-rolling <tool>    # aggiorna solo lo strumento richiesto
   ```
3. **Componenti esterni**: Tor Browser (verifica GPG, hook/aggiornatore),
   Volatility (pip pinned). Mai aggiornare durante un'attività critica.

## Regole di sicurezza operativa
- **Non** aggiornare strumenti durante un **test forense** o un'attività critica
  (riproducibilità). Congela le versioni per la durata dell'indagine.
- **Non** eseguire aggiornamenti distruttivi della **persistenza** senza backup
  (header LUKS + dati) e conferma.
- Aggiornamenti applicati a **sessioni live** valgono solo per quella sessione
  (RAM): per renderli permanenti serve la persistenza.

## Gestione delle vulnerabilità
- **SBOM** (`sbom/cyberdistro.cdx.json`) come base per lo scanning.
- In CI (roadmap): scansione dell'SBOM con un database CVE (es. OSV/Grype) a ogni
  release; blocco della release su vulnerabilità critiche senza mitigazione.
- **Avvisi**: il Security Center mostra avvisi di sicurezza critici nella
  Panoramica (roadmap: feed firmato).

## Versionamento e rilascio
- Versione in `VERSION` (SemVer + tag `-alpha/-beta`).
- `release/make-release.sh` produce SHA-256, manifest e note.
- Changelog per release in `release/RELEASE-NOTES-<versione>.md`.
- Processo di build **riproducibile** (`build/`), documentato e auditabile.

## Ripristino / rollback
- Conserva l'ultima ISO funzionante e il relativo manifest.
- Per la persistenza: backup periodico di `/home` e `/etc/cyberdistro` +
  backup dell'header LUKS (vedi `privacy/persistence/README.md`).
- Incompatibilità note documentate nelle note di rilascio.
