# Privacy & anonimato

L'anonimato è una funzione **centrale e visibile**, non un'opzione nascosta.
Basato su **Tor Browser ufficiale** (non ri-pacchettizzato in modo da alterarne
il fingerprinting) e su un **kill-switch nftables fail-closed**.

## Tre profili (`privacy/bin/privacy-mode`)

| Profilo | Comportamento |
|---|---|
| **Standard** | Navigazione normale con tracciamento ridotto; nessun kill-switch |
| **Tor Anonymity** | Tutto il traffico via Tor; traffico non-Tor **bloccato** (niente fallback diretto) |
| **Hardened** | Come Tor + restrizioni extra sul traffico in uscita (es. blocco LAN) |

```bash
sudo privacy-mode status
sudo privacy-mode tor        # attiva il kill-switch fail-closed
sudo privacy-mode hardened
sudo privacy-mode standard   # rimuove il kill-switch
```

## Kill-switch (`nftables/killswitch.nft`)
Fail-closed: se Tor non è pronto o cade, il traffico è **bloccato**, non deviato
in chiaro. Consente solo: loopback, il processo `tor`, e i pacchetti già
reindirizzati al TransPort. DNS in chiaro verso l'esterno è droppato.
Sintassi verificata con `nft -c` (vedi `tests/results/`).

## Verifiche (`privacy/tests/`)
- `check-tor-path.sh` — conferma `IsTor=true` via Tor e che una richiesta diretta
  **fallisca** con kill-switch attivo.
- `check-dns-leak.sh` — conferma resolver solo locali e che il DNS diretto esterno
  sia bloccato.
Eseguire **sul sistema live** (richiedono Tor attivo e rete reale).

## Limiti dell'anonimato — da dichiarare SEMPRE
Nessun sistema garantisce l'anonimato assoluto. Tor **non** protegge da:
- accesso ad account personali o esposizione volontaria di dati identificativi;
- tutti gli attacchi di correlazione del traffico;
- ogni forma di fingerprinting (soprattutto se si altera il browser);
- malware o compromissione del dispositivo;
- deanonimizzazione tramite file scaricati/aperti fuori dall'ambiente protetto.

Non implementiamo proxychain improvvisate né combinazioni VPN+Tor spacciate per
"automaticamente più sicure". Non alteriamo le impostazioni di Tor Browser.
