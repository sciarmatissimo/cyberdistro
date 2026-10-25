# CyberDistro

> Nome di progetto provvisorio. Distribuzione Linux live orientata alla
> cybersicurezza *autorizzata*, all'analisi forense e al reverse engineering,
> con un'esperienza desktop curata e strumenti professionali resi comprensibili
> anche a chi non è esperto.

**Stato del progetto: ALPHA in sviluppo. Nessuna release pubblica.**
Questo repository contiene il sistema di build, l'applicazione Security Center,
le configurazioni di privacy/persistenza, i test, la documentazione e gli
strumenti di rilascio. **Non** contiene un file ISO pre-generato: la ISO si
ottiene eseguendo la build su un host Debian (vedi `build/README.md`).

---

## Principio guida

La potenza degli strumenti di Kali Linux, l'attenzione alla privacy di una
distribuzione pensata per l'anonimato (Tor), le capacità di analisi forense e
reverse engineering e un'esperienza desktop elegante, accessibile e coerente —
*con la disciplina del "safe by default"*: ogni attività potenzialmente invasiva
richiede che l'utente dichiari un ambito autorizzato prima di procedere.

## Che cosa è e che cosa non è

- **È**: una base Debian stabile + strumenti Kali (via APT pinning), un desktop
  KDE Plasma con tema macOS-inspired, e il **Security Center**, un'app che
  spiega, guida e lancia gli strumenti con configurazioni sicure predefinite.
- **Non è**: un fork cosmetico di Kali; un insieme di exploit pronti all'uso;
  uno strumento per attaccare sistemi di terzi. Non include malware, payload
  offensivi pre-confezionati, né automazioni che eseguano attacchi senza una
  scelta esplicita e un ambito autorizzato dichiarato dall'operatore.

## Mappa delle fasi (vedi `docs/architecture/02-roadmap.md`)

| Fase | Contenuto | Stato in questo repo |
|------|-----------|----------------------|
| 1 | Ricerca e architettura | ✅ documentata |
| 2 | Prototipo avviabile (build system) | 🟡 config completa, build da eseguire su host |
| 3 | Security Center (core + GUI + modalità) | 🟡 core funzionante e testato; GUI scheletro |
| 4 | Privacy (Tor, kill-switch, DNS) | 🟡 ruleset e verifiche reali; integrazione da testare su ISO |
| 5 | Persistenza cifrata (LUKS2) | 🟡 script reali; da testare end-to-end su hardware/VM |
| 6 | Strumenti professionali (wrapper) | 🟡 wrapper reali per inventario/forense/privacy |
| 7 | Test e rilascio | 🟡 suite eseguibile + tooling checksum/SBOM |

Legenda: ✅ completo · 🟡 reale ma incompleto/non testato end-to-end · ❌ assente.
Lo stato aggiornato e le limitazioni note sono in `docs/architecture/03-status.md`.

## Primo avvio (login e credenziali)

La sessione live entra **automaticamente** nel desktop (autologin), senza
chiedere password. Le credenziali dell'utente live, necessarie per `sudo` e per
un eventuale login manuale, sono:

| Utente | Password |
|--------|----------|
| `analyst` | `cyberdistro` |

La sessione predefinita è **Plasma (X11)** per la massima compatibilità; dopo il
logout si può scegliere **Plasma (Wayland)** dal menu "Session" di SDDM.
Con la persistenza cifrata attiva, cambia la password al primo accesso.

## Struttura del repository

```
build/            Configurazione live-build (Debian) e script di build riproducibile
desktop/          Configurazioni del desktop (KDE Plasma, tema, layout)
security-center/  Codice sorgente dell'app principale (Python: core + GUI)
tools/            Wrapper e integrazioni degli strumenti
privacy/          Kill-switch nftables, test DNS/Tor, profili privacy
forensics/        Workflow e configurazioni forensi
tests/            Test automatici e risultati reali
docs/             Manuali per principianti, professionisti e manutentori
licenses/         Inventario licenze e attribuzioni
sbom/             Distinta dei componenti software (generatore + output)
release/          Manifest, checksum e note di rilascio
iso/              Destinazione della ISO generata + relativi checksum (vuota finché non si builda)
```

## Build rapida (su host Debian 12/13 amd64)

```bash
sudo apt-get install live-build
cd build
sudo ./build.sh        # produce ../iso/CyberDistro-PC-x86_64.iso
```

Dettagli, requisiti e troubleshooting: `build/README.md`.

## Avvertenza legale

Questo software è destinato ad **attività autorizzate**: apprendimento, ricerca,
e test di sicurezza su sistemi di cui si possiede o si è ricevuta esplicita
autorizzazione scritta. L'uso contro sistemi di terzi senza autorizzazione è
illegale nella maggior parte delle giurisdizioni. Le misure "safe by default"
del Security Center registrano un ambito dichiarato ma **non** costituiscono né
sostituiscono un'autorizzazione legale. La responsabilità è interamente
dell'operatore. Vedi `licenses/NOTICE.md`.

## Licenza

Il codice originale di questo progetto (Security Center, script, documentazione)
è rilasciato sotto **GPL-3.0-or-later** (vedi `LICENSE`). Gli strumenti di terze
parti mantengono le proprie licenze: vedi `sbom/` e `licenses/`.
