# Guida per principianti

Benvenuto. Questa guida ti porta dal nulla alla prima operazione di sicurezza
**in modo sicuro e comprensibile**, senza bisogno di conoscere i comandi Linux.

## 1. Cos'è CyberDistro
Un sistema operativo che parte da una chiavetta USB. Contiene strumenti
professionali di sicurezza informatica, resi facili da usare dal **Security
Center**. Tutto gira dalla chiavetta: il computer e il suo disco **non** vengono
modificati, a meno che tu non lo chieda esplicitamente.

## 2. Regola d'oro (leggila davvero)
Usa questi strumenti **solo** su sistemi **tuoi** o per cui hai
un'**autorizzazione scritta**. Testare sistemi altrui senza permesso è illegale.
Il Security Center ti chiede sempre di dichiarare *chi è il proprietario* e
*quali bersagli sei autorizzato a testare*: questo serve a proteggerti e a
ricordarti la responsabilità. **Non** è un permesso legale: quello devi averlo tu.

## 3. Preparare la chiavetta
1. Scarica l'immagine `CyberDistro-PC-x86_64.iso`.
2. **Verifica l'integrità** (importante): apri un terminale dove hai scaricato il
   file e controlla che l'impronta SHA-256 corrisponda a quella pubblicata
   (istruzioni in `release/`).
3. Scrivila su una chiavetta (almeno 16 GB) con **balenaEtcher** (semplice) o
   **Rufus** su Windows, scegliendo la modalità "immagine DD".
4. Inserisci la chiavetta nel PC e, all'accensione, entra nel menu di avvio
   (di solito un tasto tra `F12`, `F10`, `Esc` o `F2`) e scegli la chiavetta.
   Se non parte: vedi "Risoluzione problemi".

## 4. Primo avvio
- Scegli **Live** per una sessione temporanea (niente viene salvato).
- Scegli **persistence** se hai creato la memoria cifrata (ti chiede la password).
- Arrivi a un desktop pulito, in stile moderno: in alto la barra di stato
  (menu, orologio, rete, Bluetooth, batteria), in basso la barra delle
  applicazioni con: menu, **Impostazioni di sistema**, **Security Center**, File,
  Terminale, Tor Browser.

## 5. Apri il Security Center
È l'icona con lo scudo nella **barra in basso a sinistra, subito a destra delle
Impostazioni di sistema**. In modalità **Principiante** (quella iniziale) il menu
a sinistra è ridotto all'essenziale:
- **Esplora**: chi c'è sulla tua rete Wi‑Fi e quali dispositivi Bluetooth hai intorno.
- **Panoramica**: quattro grandi pulsanti (Esplora la rete, Naviga anonimo,
  Verifica un file, Impara) e lo stato di rete/Tor/Bluetooth a colpo d'occhio.
- **Privacy**: modalità Standard / Anonimato Tor / Rafforzata e Tor Browser.
- **Impara**: cosa fa ogni strumento, in parole semplici.

Le voci avanzate (Strumenti, Progetti, Report) compaiono passando a
**Professionista** o **Esperto** dal selettore in basso a sinistra. Il cambio è
reversibile e non cancella nulla.

## 6. La tua prima operazione: Esplora la tua rete
Obiettivo: vedere quali dispositivi sono collegati alla **tua** rete.
1. Security Center → **Esplora** (scheda *Rete Wi‑Fi / cablata*). La tua rete è
   già selezionata (es. `Wi‑Fi «CasaMia» — 192.168.1.0/24`).
2. Premi **Cerca dispositivi**. Ti viene chiesto di confermare che è la tua rete
   (o che sei autorizzato a osservarla): spunta la casella e conferma.
3. Dopo qualche secondo compaiono i dispositivi come **icone**: il tuo computer,
   il router, telefoni, stampanti, TV, dispositivi «smart»… Se un tipo non è
   riconoscibile viene mostrato come dispositivo generico (non viene inventato).
4. **Clicca su un'icona** per i dettagli: indirizzo IP, indirizzo fisico (MAC),
   produttore, nome, se è il router, con una spiegazione in italiano.
5. Scheda **Bluetooth** → **Cerca dispositivi**: ascolta per alcuni secondi i
   dispositivi vicini (cuffie, telefoni, smartwatch…) e li mostra allo stesso modo.
   Non si connette e non accoppia nulla.

Cosa succede davvero: per la rete viene eseguito un controllo di presenza
(`nmap -sn`) **solo** sulla rete a cui sei connesso — non puoi inserire altri
bersagli qui; per il Bluetooth si usa `bluetoothctl` in sola lettura. In modalità
Professionista/Esperto il comando esatto è mostrato nella finestra dei dettagli.

Vuoi sapere *quali servizi* espone un dispositivo? Passa a **Professionista**,
crea un **Progetto** con il tuo intervallo autorizzato e usa **Strumenti →
Inventario di rete (Nmap)**. Se provi un bersaglio **fuori** dall'ambito
autorizzato, il sistema ti **blocca**: è voluto.

## 7. Navigare in modo anonimo
- Barra di stato → icona privacy → scegli **Anonimato Tor**.
- Si attiva il *kill-switch*: se Tor non funziona, la rete viene **bloccata**
  invece di esporti. Niente connessioni "di nascosto".
- Apri **Tor Browser** (quello ufficiale). Verifica lo stato nella Panoramica.
- **Importante**: Tor non ti rende invisibile se accedi ai tuoi account personali,
  scarichi file e li apri fuori, o se il computer è già infetto. Leggi gli avvisi.

## 8. Spegnere
Menu → Esci/Spegni. In modalità Live, i dati della sessione in RAM vengono persi.
Attendi il messaggio prima di rimuovere la chiavetta.

## 9. Risoluzione problemi (rapida)
| Problema | Cosa fare |
|---|---|
| Non parte dalla USB | Entra nel menu di avvio (F12/Esc…) e scegli la chiavetta; disattiva **Secure Boot** nel BIOS/UEFI |
| Wi-Fi assente | Alcune schede richiedono firmware/adattatori esterni; vedi la matrice di compatibilità |
| È lento | Usa una porta/chiavetta USB 3.x; attiva l'opzione *toram* al boot |
| Ho dimenticato la password della persistenza | Non è recuperabile (è cifrata). Ricrea la persistenza; i vecchi dati restano illeggibili |

Per approfondire: `docs/professional/guida-professionale.md`.
