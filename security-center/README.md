# Security Center

Front-end guidato e *safe-by-default* per gli strumenti di sicurezza di
CyberDistro. Architettura a due livelli:

- **`core/`** — motore headless, nessuna dipendenza GUI. Catalogo strumenti,
  rilevamento capacità, gating autorizzazioni, esecuzione comandi, parsing,
  gestione progetti e report. Usabile da CLI e testabile.
- **`gui/`** — interfaccia PySide6 (solo presentazione; chiama il core).

## Uso da CLI (headless, funziona senza GUI)

```bash
cyberdistro-sc doctor                 # stato sistema + capacità strumenti
cyberdistro-sc catalog                # elenca gli strumenti per categoria
cyberdistro-sc explain nmap-inventory # spiega cosa fa, quando usarlo, permessi
cyberdistro-sc project new "Audit ACME" --owner "ACME SpA" --scope 192.168.50.0/24
cyberdistro-sc run nmap-inventory --project "Audit ACME" --target 192.168.50.0/24
cyberdistro-sc report "Audit ACME" --format json
```

Ogni operazione attiva richiede un **progetto** con **proprietario** e **ambito
autorizzato** dichiarati, e una conferma esplicita prima di azioni invasive.
Questo registra l'intenzione dichiarata dell'operatore; **non** è
un'autorizzazione legale (vedi NOTICE).

## Tre modalità

| Modalità | Cosa cambia |
|---|---|
| Beginner | Procedure guidate, default sicuri, spiegazioni, nessun comando Linux richiesto |
| Professional | Parametri esposti, workflow, export report |
| Expert | Tutti i parametri, terminale, comando sottostante mostrato e riproducibile |

Il cambio di modalità **non** altera silenziosamente risultati o configurazioni.

## Test

```bash
cd security-center && python3 -m unittest discover -s tests -v
```
(oppure la suite di repo in `../tests/`)
