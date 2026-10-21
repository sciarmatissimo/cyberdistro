# 02 — Roadmap per fasi verificabili

Ogni fase ha criteri di accettazione. Una funzionalità è "fatta" solo se supera
i suoi test e non è un mockup.

## Fase 1 — Ricerca e architettura ✅
- [x] Analisi base (Debian + Kali pinning); alternative valutate (Tails, Parrot, Qubes)
- [x] Requisiti funzionali/non funzionali, rischi, criteri di accettazione
- [x] Struttura del progetto definita

## Fase 2 — Prototipo avviabile 🟡
- [x] Configurazione `live-build` completa (package-lists, hooks, GRUB UEFI+BIOS)
- [x] `build.sh` riproducibile con requisiti documentati
- [ ] ISO generata su host Debian  ← **richiede host con rete ai mirror + privilegi**
- [ ] Boot verificato in VM (QEMU/VirtualBox) e su hardware fisico
- [ ] Desktop KDE avvia con tema applicato

## Fase 3 — Security Center 🟡
- [x] Core headless: catalogo, rilevamento capacità, gating, esecuzione, parsing
- [x] Modalità Beginner/Professional/Expert (modello)
- [x] Wrapper reali: inventario rete (nmap), hashing forense, stato privacy
- [x] Test unitari del core (eseguiti, vedi `tests/results/`)
- [ ] GUI PySide6 completa (presente scheletro navigabile)
- [ ] Documentazione contestuale in-app completa

## Fase 4 — Privacy 🟡
- [x] Ruleset kill-switch nftables fail-closed + script verifica
- [x] Script test DNS-leak / percorso Tor (logica reale)
- [ ] Integrazione Tor Browser nella ISO + test end-to-end su sistema live
- [ ] Verifica comportamento a caduta connessione su hardware reale

## Fase 5 — Persistenza cifrata 🟡
- [x] Script setup LUKS2 non distruttivo + unlock (reali)
- [ ] Test end-to-end su chiavetta reale (crea/sblocca/recupera/riavvii ripetuti)
- [ ] Documentazione backup/recupero passphrase verificata sul campo

## Fase 6 — Strumenti professionali 🟡
- [x] Categorie prioritarie modellate nel catalogo
- [x] Wrapper grafici reali (non fittizi) per le operazioni sicure prioritarie
- [ ] Reporting PDF/HTML/JSON completo (JSON presente; PDF/HTML in roadmap)
- [ ] Verifica "ogni pulsante fa davvero l'azione" su sistema live

## Fase 7 — Test e rilascio 🟡
- [x] Suite test eseguibile localmente + risultati
- [x] Tooling SHA-256 / manifest / note di rilascio
- [x] Generatore SBOM (CycloneDX) + inventario licenze
- [ ] Test boot USB su hardware reale
- [ ] Scansione dipendenze in CI su ISO reale
- [ ] Firma ISO e pubblicazione

## Definizione di completamento (prima release pubblica)
Vedi `docs/architecture/03-status.md` per lo stato puntuale di ciascun criterio
del capitolato §18. **Non** si dichiara una release pubblica finché la ISO non
boota realmente sulle configurazioni di riferimento dichiarate.
