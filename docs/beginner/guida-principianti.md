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
  (rete, privacy, batteria), in basso il dock con le app, al centro la ricerca.

## 5. Apri il Security Center
È l'app con lo scudo. Da qui:
- **Panoramica**: lo stato del sistema e della privacy.
- **Strumenti**: elenco per obiettivo (rete, web, forense, ecc.). Ogni strumento
  spiega *cosa fa*, *quando usarlo* e *quali permessi servono*.
- Lascia la modalità su **Principiante**: ti guida passo-passo con scelte sicure.

## 6. La tua prima operazione: inventario della tua rete di casa
Obiettivo: scoprire quali dispositivi sono collegati alla **tua** rete.
1. Security Center → **Progetti** → *Nuovo progetto*. Dai un nome (es. "Casa
   mia"), indica te stesso come proprietario e inserisci l'intervallo della tua
   rete (il Security Center lo rileva e te lo propone, es. `192.168.1.0/24`).
2. Vai su **Strumenti → Inventario di rete** e premi **Mostra comando** per
   vedere esattamente cosa verrà eseguito (trasparenza totale).
3. Premi **Esegui**. Vedrai l'avanzamento e poi un elenco chiaro di dispositivi e
   servizi, con spiegazioni.
4. Premi **Esporta report** per avere un PDF/HTML/JSON ordinato.

Se provi un bersaglio **fuori** dal tuo intervallo autorizzato, il sistema ti
**blocca**: è voluto.

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
