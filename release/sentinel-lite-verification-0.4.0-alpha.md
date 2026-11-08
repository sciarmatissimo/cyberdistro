
## Cosa c'è di nuovo: vedere e controllare l'intera rete (fase 2)

Tre strumenti facoltativi nella scheda «Attività AI», spenti per impostazione predefinita, più un
nuovo livello di autonomia. Gli strumenti che guardano l'intera rete chiedono prima di confermare che
la rete è tua.

- **2a — Mappa completa della rete (censimento).** Con «Questa è la mia rete» e «Mappa completa»
  attivi, il sensore manda ogni pochi minuti una richiesta ARP a ogni indirizzo della sottorete e
  annota chi risponde, così l'agente trova anche i dispositivi che non parlano mai con questo PC e può
  proporre di esaminarli con Nmap. Usa la stessa presa di rete del sensore passivo (un solo servizio
  con privilegi di rete); si rifiuta su sottoreti troppo grandi.
- **2b — Ispeziona il traffico della rete (ispezione a tempo).** Per 1–10 minuti questo PC fa passare
  da sé il traffico degli altri dispositivi **continuando a inoltrarlo** (la rete non si interrompe),
  così Suricata e Zeek vedono *chi parla con chi*; il contenuto cifrato resta illeggibile. Finestra di
  avviso con il richiamo legale (in Italia artt. 617 e seguenti) e spunta di consenso obbligatoria.
  Si ferma da sola allo scadere del tempo (triplo fermo di sicurezza), ripristina la rete e guarisce
  le cache ARP; `sentinel-inspect` non tocca mai questo PC, il router o i DNS e lavora solo su
  sottoreti private. Al termine mostra un riepilogo per dispositivo.
- **2c — Controlla questa rete (Wi-Fi e DNS).** Segnala Wi-Fi aperto o debole (WEP/WPA1), reti con lo
  stesso nome ma sicurezza diversa (possibile «rete gemella») e un DNS che risponde a un nome
  inesistente (possibile dirottamento), con livello OK/Attenzione/Pericolo.
- **Protezione automatica (livello «auto»).** Esegue da sola le azioni locali e reversibili (blocco su
  questo PC, prova, router fissato); esami e ispezioni restano da approvare. L'esecuzione automatica
  avviene nella sessione dell'utente tramite `pkexec` (azione polkit dedicata, percorsi fissi): il
  servizio di sistema dell'agente non riceve mai sudo senza password.

## Verifica in laboratorio (8 novembre 2026)

Laboratorio: ISO Lite avviata in QEMU come chiavetta USB su una rete virtuale con router (DHCP/DNS a
192.168.77.254). I clic sono stati fatti nel Security Center vero, nella sessione LXQt, quindi le
azioni sono passate da `pkexec`/`sudo`. Il PC virtuale ha preso l'indirizzo 192.168.77.111.

| Prova | Risultato |
| --- | --- |
| **2a** Censimento attivo (/24) | il sensore registra `{"kind":"census","sent":253}`: una richiesta ARP a ogni indirizzo utile della sottorete |
| **2b** «Ispeziona il traffico» → finestra di consenso | avviso con richiamo legale e spunta obbligatoria; «Avvia ispezione» disabilitato finché non si conferma |
| **2b** Avvio ispezione (tutta la rete) | stato `running`, inoltro IP a 1, banner «Ispezione del traffico in corso … mancano 2:59» |
| **2b** «Ferma ispezione» | stato `idle`, inoltro IP tornato a 0, file di stato del worker rimosso, nessun processo residuo; router di nuovo raggiungibile, DNS funzionante, rotta predefinita intatta (rete ripristinata) |
| **2b** Riepilogo a fine ispezione | finestra «Ispezione del traffico — risultati» (poco traffico sulla rete di prova) |
| **2c** «Controlla questa rete (Wi-Fi e DNS)» | finestra «Controllo della rete»: «[OK] Il DNS della rete risponde correttamente — un nome inesistente viene segnalato come tale» (nessuna Wi-Fi: PC via cavo) |
| **2c auto** Proposta router fissato con livello «Protezione automatica» | l'agente esegue **da solo** il router fissato: voce ARP `PERMANENT` sulla scheda vera del router; la proposta passa a ATTIVA |

Prove automatiche: **76 test** (tra cui i nuovi `test_network_tools.py` — frame ARP, censimento,
rilevamento port mirror, controlli Wi-Fi/DNS, riepilogo per dispositivo — e `test_gui_job.py` sulla
consegna affidabile dei callback). Test della GUI offscreen superato.

Difetto trovato nel laboratorio e corretto: il controllo Wi-Fi/DNS (2c) restava bloccato su «Controllo
in corso…». Causa: l'oggetto che porta il risultato di un lavoro in background veniva distrutto appena
il lavoro finiva e, se il segnale non era ancora stato consegnato all'interfaccia, il callback andava
perso — un difetto latente di **tutte** le azioni asincrone (blocco, ispezione, controllo rete,
«Spiegamelo»). Corretto tenendo vivo ogni lavoro finché il suo callback non è stato eseguito
(`gui/app.py`, con `test_gui_job.py` a guardia). Dopo la correzione, nel laboratorio il controllo
Wi-Fi/DNS mostra il risultato e il pulsante torna attivo; ispezione e protezione automatica eseguono
regolarmente.

## ISO pubblicata

Costruita da GitHub Actions nella release `sentinel-lite-v0.4.0-alpha`. Dimensione e SHA-256 della ISO
pubblicata, e l'esito della riprova dopo il download (checksum, avvio con Secure Boot, strumenti 2a/2b/2c),
vengono aggiunti qui dopo la verifica.

## Non ancora verificato
- Hardware reale (il laboratorio è virtuale).
- «Spiegamelo (AI)» nel laboratorio (la macchina virtuale non aveva RAM libera sufficiente per il modello).
- Ispezione con più dispositivi reali contemporaneamente (nel laboratorio il traffico di prova era scarso).
