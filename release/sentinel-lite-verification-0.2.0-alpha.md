
## Cosa cambia rispetto alla Lite 0.1.0

Nasce da una prova reale su un portatile Dell: usando «Esamina questo dispositivo (Nmap)» il
Security Center segnalava *"Qualcuno sta esplorando le porte"*, un *"traffico sospetto"* tra il router
e il PC (una firma DNS informativa) e molti *"Nuovo dispositivo"*, e proponeva di bloccare il router.

- **Le tue scansioni non sono più attacchi.** Gli esami avviati dal Security Center vengono
  registrati; il traffico che producono verso il loro bersaglio diventa **«Scansione avviata da te»**
  (informativa). Se invece è questo PC a scansionare senza che tu l'abbia chiesto da Sentinel,
  compare **«Questo PC sta esaminando la rete, ma non l'hai chiesto da Sentinel»** (stato giallo):
  può essere un programma indesiderato. Un attacco di un altro dispositivo nello stesso momento resta
  un allarme.
- **Sentinel sa chi è chi**: le schede dicono «il router (…)» e «questo PC (…)», i consigli si
  adattano e il pulsante «Blocca» è disattivato per il router, per questo PC e per gli eventi
  informativi.
- **Firme informative** di Suricata (*Not Suspicious Traffic* ecc.) registrate, non più allarmi.
- **Dispositivi trovati dalla tua scansione** indicati come tali e raggruppati in una riga.
- **Esame spiegato porta per porta**: cos'è il servizio, rischio alto/medio/basso, cosa fare
  (Telnet, FTP, RDP, VNC, SMB, telecamere RTSP, database…). Il risultato resta nella scheda del
  dispositivo. L'esame usa `-Pn`, così i dispositivi che ignorano il ping non risultano "spenti".
- **Assistente più utile**:
  - risposte immediate su un indirizzo ("chi è 192.168.1.20?"), sui conteggi per tipo e sugli esami fatti;
  - **piano d'azione** ordinato ("Cosa devo fare adesso?", "devo preoccuparmi?", "come proteggo la
    rete?"): allarmi, porte rischiose, dispositivi nuovi o non esaminati, buone pratiche per il router;
  - per le domande libere il modello AI riceve il quadro completo della rete (ruoli, dispositivi,
    allarmi, esami e rischi delle porte), con regole più strette, e se una risposta viene scartata
    se ne vede il motivo.
- **Corretto**: il database era leggibile ma non scrivibile dal Security Center, quindi «Segna come
  gestito» e la cronologia delle azioni (blocchi) non venivano salvati.

## Verifica (8 novembre 2026)

ISO avviata in QEMU come chiavetta USB, sessione in italiano, Suricata/Zeek/sensore reali:

| Prova | Risultato |
| --- | --- |
| Esame di un dispositivo come lo fa il Security Center (registrazione + `nmap -Pn -sT -F`) | ✅ un solo evento «Scansione avviata da te», stato **verde** |
| Scansione di 300 porte dallo stesso PC, non avviata da Sentinel | ✅ «Questo PC sta esaminando la rete, ma non l'hai chiesto da Sentinel», stato **giallo** |
| «Qualcuno sta cercando di attaccare la mia rete?» | ✅ indica la scansione non richiesta con origine «questo PC» |
| «Cosa devo fare adesso?» | ✅ piano d'azione ordinato |
| Database scrivibile dall'utente `analyst` | ✅ `sentinel.db` 0660 |

Prove automatiche: 42 test (correlazione, verificatore, nuove regole, conoscenza delle porte, piano
d'azione). Modello Qwen3.5-2B provato sul nuovo quadro della rete: risposte corrette su domande
semplici, ma su domande complesse può attribuire male gli eventi; per questo i casi comuni hanno
risposte deterministiche e il verificatore resta attivo. Server del modello misurato a 2,0–2,3 GB.

## Non ancora verificato
- Hardware reale con questa versione (la Lite 0.1.0 si avvia sul Dell).
- Una vera porta rischiosa (es. Telnet) su un dispositivo reale: la spiegazione è provata nei test.
