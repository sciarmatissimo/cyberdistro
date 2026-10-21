# 03 — Stato puntuale e limitazioni note

Confronto onesto con la "Definizione di completamento" del capitolato (§18) e con
gli output obbligatori (§4). **Legenda:** ✅ fatto/verificato qui · 🟡 implementato
ma non verificabile in questo ambiente · ⛔ non ancora fatto.

## Definizione di completamento (§18)

| Criterio | Stato | Note |
|---|---|---|
| L'ISO esiste realmente | ⛔ | La **configurazione di build** esiste ed è reale; la ISO va generata su host Debian (la sandbox di sviluppo non ha mirror/chroot privilegiato). Non è stato inventato alcun file ISO. |
| L'ISO è avviabile sulle config di riferimento | ⛔ | Richiede build + test su VM/hardware. |
| Il desktop funziona | 🟡 | KDE Plasma configurato via package-list + includes; non avviato qui. |
| Il Security Center è operativo | ✅ (core/CLI) 🟡 (GUI) | Core e CLI **funzionano e sono testati** (22 test). GUI = scheletro PySide6 non eseguito qui. |
| Le funzionalità principali non sono mockup | ✅ | Wrapper reali (nmap-inventory, forensic-hash, privacy-status) con parsing reale e gating. Nessun pulsante finto. |
| La persistenza cifrata è verificata | 🟡 | Script LUKS2 reali e con `bash -n` OK; test end-to-end su chiavetta non eseguibile qui. |
| I workflow principali sono testati | ✅ (logica) 🟡 (su live) | Catena autorizzazione→esecuzione→report testata via CLI. |
| Navigazione Tor integrata e verificata | 🟡 | Integrazione (hook GPG-verify) + kill-switch (syntax OK) + script di verifica reali; verifica end-to-end richiede sistema live. |
| Risultati dei test disponibili | ✅ | `tests/results/` contiene output **reali**. |
| Documentazione completa | 🟡 | Guide principianti/professionisti/manutentori presenti; da ampliare con la GUI. |
| Licenze e componenti inventariati | ✅ | `sbom/cyberdistro.cdx.json` (120 comp.) + `licenses/`. |
| Limiti noti dichiarati | ✅ | Questo documento. |
| La build può essere riprodotta | ✅ (istruzioni) | `build/` + `build/README.md`; riproducibilità dipende da mirror/pinning. |

## Output obbligatori (§4) — stato
1. ISO x86-64 avviabile e verificata — ⛔ (build su host; vedi sopra)
2. Sistema Live funzionante — 🟡 (configurato)
3. Procedura USB — ✅ (`build/README.md`)
4. Persistenza cifrata — 🟡 (script reali)
5. Desktop completo e coerente — 🟡 (configurato)
6. Security Center (centro di controllo) — ✅ core/CLI, 🟡 GUI
7. Interfacce guidate per categorie — 🟡 (3 wrapper reali; altre categorie modellate)
8. Privacy/anonimato configurabile — 🟡 (profili + kill-switch reali)
9. Documentazione principianti/professionisti — ✅ presente
10. Script/config per riprodurre la build — ✅
11. Test automatici + risultati + limiti — ✅
12. SBOM con versioni e licenze — ✅ (versioni "resolved-at-build", non inventate)
13. SHA-256 ISO + istruzioni verifica — 🟡 tooling pronto (`release/`), hash dopo build
14. Piano aggiornamento/manutenzione/vulnerabilità — ✅ (`docs/maintainer/update-and-maintenance.md`)

## Limitazioni note (dichiarazione esplicita)
- **ISO non generata in questo ambiente**: nessun accesso ai mirror Debian/Kali
  né a chroot privilegiato. La config è reale; la ISO si ottiene con `build.sh`
  su un host adeguato. Nessun artefatto ISO è stato simulato.
- **GUI non eseguita**: PySide6 assente nella sandbox. Il codice GUI è uno
  scheletro navigabile che chiama il core; i pannelli non implementati lo
  dichiarano esplicitamente invece di fingere.
- **Nessun test su hardware reale**: boot USB, Secure Boot, Wi-Fi monitor mode,
  sospensione/ripresa non sono stati testati.
- **Secure Boot**: non firmato in alpha.
- **Anonimato**: nessuna garanzia assoluta (vedi `privacy/README.md`).
- **Wipe forense di RAM/flash**: non garantibile; non promesso.
- **Reporting PDF/HTML**: JSON e HTML implementati e testati; PDF dipende da
  reportlab (presente → funziona), layout minimale.
- **Categorie di strumenti**: tutte presenti nelle package-list; i *wrapper
  guidati* reali coprirono finora inventario rete, hashing forense e stato
  privacy. Le altre voci sono lanciabili nella forma originale e modellate nel
  catalogo, con wrapper guidati pianificati (Fase 6).

Questo documento va aggiornato a ogni avanzamento. Non dichiarare "fatto" ciò che
non supera i propri test.
