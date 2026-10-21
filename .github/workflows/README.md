# GitHub Actions — workflow

Due workflow, validati con `actionlint` (nessun problema).

## `ci.yml` — CI veloce
**Quando:** ogni push su `main`/`master`, ogni PR, o manualmente.
**Cosa fa:** esegue `tests/run-all.sh` (22 test del Security Center, `shellcheck`,
sintassi kill-switch `nft -c`, generazione SBOM) e carica `tests/results/` +
SBOM come artifact. **Non** builda la ISO. Dura pochi minuti.

## `build-iso.yml` — build della ISO
**Quando:**
- **manuale** (`workflow_dispatch`) con opzioni:
  - `full_build` (default `true`): build completa. Se `false`, valida solo la
    configurazione `live-build` (`lb config`), rapido.
  - `tbb_version`: versione di Tor Browser da includere.
- **push di un tag `v*`**: build completa + creazione di una **Release**
  (prerelease) con checksum, SBOM e note.

**Come funziona:** la build gira in un container **Debian trixie privilegiato**
(`docker run --privileged`), perché `live-build` richiede root e chroot/mount/loop.
Passi: libera spazio sul runner → cache dei pacchetti `live-build` → `build.sh`
nel container → SBOM + SHA-256 + manifest + note (`release/make-release.sh`) →
upload artifact `cyberdistro-iso`.

### Requisiti e limiti (dichiarati)
- **Durata:** decine di minuti. `timeout-minutes: 120`.
- **Disco:** la ISO con questi strumenti può essere grande. Il workflow libera
  ~25 GB sul runner hosted; per immagini molto grandi può servire un **runner
  self-hosted o più capiente**. Se la build fallisce con "no space left",
  è questo il motivo.
- **Rete:** servono `deb.debian.org`, `http.kali.org`, `dist.torproject.org`.
- **Release asset > 2 GiB:** GitHub limita gli asset di Release a 2 GiB. Se la
  ISO supera il limite, resta disponibile come **artifact** del workflow e la
  Release riceve solo checksum + SBOM + note, con avviso esplicito.
- **Secure Boot:** la ISO alpha non è firmata (vedi `docs/architecture/03-status.md`).

### Uso rapido
```text
# Build manuale completa:
Actions → "Build ISO" → Run workflow → full_build = true

# Solo validazione config (veloce):
Actions → "Build ISO" → Run workflow → full_build = false

# Release automatica:
git tag v0.1.0 && git push origin v0.1.0
```

### Nota di sicurezza (supply chain)
Usiamo solo action ufficiali (`actions/checkout`, `actions/cache`,
`actions/upload-artifact`) e `gh` preinstallato per le Release — nessuna action
di terze parti. Per irrigidire ulteriormente, si possono **pinnare le action al
commit SHA** invece del tag `@v4`. I permessi del token sono minimi
(`contents: read` in CI, `contents: write` solo per creare Release).
