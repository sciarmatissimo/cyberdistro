# Guida professionale

Per chi conosce la sicurezza offensiva/forense e vuole efficienza, controllo e
report ripetibili.

## Modalità operative
- **Professional**: parametri esposti, workflow, export report. Il comando
  sottostante è mostrabile su richiesta.
- **Expert**: tutti i parametri, terminale, comando sempre visibile e
  riproducibile, flag aggiuntivi (`--extra` nella CLI). Nessuna modalità altera
  silenziosamente i risultati: l'argv eseguito è sempre registrato nel progetto.

## CLI (headless) — equivalente completo della GUI
```bash
cyberdistro-sc doctor
cyberdistro-sc catalog
cyberdistro-sc explain nmap-inventory
cyberdistro-sc project new "Audit ACME" --owner "ACME SpA" --scope 192.168.50.0/24
cyberdistro-sc run nmap-inventory --project "Audit ACME" \
    --target 192.168.50.0/24 --profile service-inventory --mode expert --dry-run
cyberdistro-sc run nmap-inventory --project "Audit ACME" \
    --target 192.168.50.0/24 --profile service-inventory --yes
cyberdistro-sc report "Audit ACME" --format html > report.html
cyberdistro-sc report "Audit ACME" --format pdf --out report.pdf
```
I progetti vivono in `$CYBERDISTRO_PROJECTS` (default
`~/.local/share/cyberdistro/projects`); puntalo alla persistenza cifrata.

## Gating safe-by-default (come funziona davvero)
- Ogni operazione **attiva** richiede un progetto con *owner* e *scope*.
- Lo *scope* accetta IP/CIDR/hostname; il motore verifica l'appartenenza
  (`Authorization.covers`). Un bersaglio fuori scope viene **rifiutato**
  (exit 4), non eseguito.
- Le operazioni `active_intrusive` richiedono conferma esplicita (`--yes` o
  dialog GUI).
- Ogni esecuzione è loggata nel progetto: timestamp, argv esatto, returncode,
  e hash delle evidenze salvate (catena di custodia).

## Flusso di penetration test autorizzato (consigliato)
1. **Progetto + ambito**: registra committente, sistemi, finestre temporali,
   limiti di intensità. Allega l'autorizzazione (fuori banda).
2. **Ricognizione passiva** prima di quella attiva.
3. **Inventario** (`nmap-inventory`, profili crescenti). Parti da `discovery`.
4. **Validazione controllata** delle evidenze; distingui confermato/probabile/
   possibile/falso-positivo (campo `confidence` nei finding).
5. **Documentazione**: finding con gravità motivata; i suggerimenti AI sono
   marcati `source=ai` e separati dai dati rilevati dagli strumenti.
6. **Report** JSON (interscambio), HTML (lettura), PDF (consegna). Il JSON è lo
   schema canonico per import in piattaforme di vulnerability management.

## Forense e IR
- `forensic-hash`: hashing in streaming (gestisce immagini grandi), verifica
  contro hash atteso, log della catena di custodia. Lavora su **copie**.
- Principio: ripetibilità e tracciabilità. Report con data/ora, versioni
  strumenti, parametri.
- **Write-blocking**: il campo `write_blocker_declared` riflette una
  *dichiarazione* dell'operatore, non una garanzia del sistema. Per garanzie usa
  un write-blocker hardware.

## Reverse engineering / malware
- Analisi **statica per prima** (`file-triage`, Ghidra, radare2). I campioni
  **non** vengono eseguiti automaticamente.
- Ambiente isolato consigliato (VM senza rete, snapshot). Niente accesso a rete,
  USB o filesystem host durante l'analisi dinamica.

## Privacy avanzata
- `privacy-mode {standard|tor|hardened|off}` gestisce il kill-switch nftables.
- `privacy/tests/check-tor-path.sh` e `check-dns-leak.sh` verificano percorso Tor
  e assenza di leak (eseguire sul sistema live).
- Non combinare VPN+Tor "a scatola chiusa"; non modificare Tor Browser.

## Estendere il catalogo
Aggiungi strumenti in `security-center/src/cyberdistro_sc/data/catalog.yaml`
(documentazione + activity + eventuale `wrapper`). Un wrapper guidato è un modulo
in `tools/` che espone `explain()`, `plan()` e `run(...)` e usa
`Authorization.require()` per il gating. Vedi `network_inventory.py` come modello.
