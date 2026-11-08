
## Cosa c'è di nuovo: l'agente di protezione (fase 1)

- **Agente Sentinel** (servizio `sentinel-agent`, senza privilegi): segue gli allarmi e prepara le
  azioni di difesa con regole scritte a mano. Il modello AI non decide e non esegue nulla: spiega le
  proposte, con il verificatore.
- **Scheda «Attività AI»** nel Security Center:
  - **Da approvare**: ogni proposta con perché, cosa succede se approvi e contesto raccolto, con
    i pulsanti Approva, Rifiuta e Spiegamelo (AI);
  - **Azioni attive**: per esempio blocchi con il tempo rimanente e il pulsante Annulla l'azione;
  - **Cronologia** di tutto quello che l'agente ha notato e fatto;
  - livello di autonomia, «Ferma l'agente» e un contatore nella barra laterale e in Home.
- **Livelli**: **Chiede** (predefinito) e **Osserva**.
- **Azioni**:
  - blocco di un attaccante su questo PC per 24 ore;
  - router fissato contro l'ARP spoofing;
  - 60 secondi di traffico salvati come prova;
  - esame Nmap dei dispositivi nuovi, solo su una rete dichiarata tua;
  - contesto raccolto automaticamente dai log.
- **Sicurezza**:
  - mai contro questo PC, il router o i DNS;
  - scadenze, annullamento, al massimo 12 proposte l'ora;
  - «Ferma l'agente» annulla tutto.
- Le domande di conferma del Security Center hanno pulsanti in italiano («Sì» / «No»).

## Verifica (8 novembre 2026)

Laboratorio: ISO avviata in QEMU su una rete virtuale con un router (DHCP/DNS) e un **attaccante
con una propria scheda di rete**. I clic sono stati fatti nel Security Center vero, nella sessione
LXQt, quindi le azioni sono passate da `pkexec`.

| Prova | Risultato |
| --- | --- |
| Port scan di 300 porte dall'attaccante | allarme ROSSO; l'agente raccoglie il contesto e propone **blocco 24 h** e **prova** |
| Clic su «Approva» del blocco | regola `nftables` attiva (scade dopo 24 h); le porte di questo PC risultano *filtered* per l'attaccante |
| ARP spoofing del router (risposte false con un'altra scheda) | allarme ROSSO; proposta di **fissare il router** sulla scheda vera |
| Clic su «Approva» del router fissato | voce ARP `PERMANENT` sulla scheda vera; un nuovo spoofing non la cambia più |
| Clic su «Approva» della prova | file pcap da 10 KB in `/var/lib/sentinel/evidence` |
| «Ferma l'agente» → «Sì» | proposte rifiutate, blocco tolto (porta di nuovo raggiungibile), router di nuovo appreso normalmente |

Prove automatiche: 58 test, di cui 16 sull'agente (playbook, indirizzi protetti, livelli, doppioni,
limite orario, esecuzione, annullamento, scadenza, nessun nome di rete al modello).

Difetto trovato nel laboratorio e corretto: se la scheda del router aveva anche un altro indirizzo,
l'agente poteva scambiarlo per il router. Ora il router e gli indirizzi di questo PC vengono letti dal
kernel.

## Non ancora verificato
- Hardware reale (il laboratorio è virtuale).
- «Spiegamelo (AI)» nel laboratorio (la macchina virtuale non aveva RAM libera sufficiente per il modello).
- Esame Nmap proposto dall'agente su una rete dichiarata propria (provato nei test automatici).
