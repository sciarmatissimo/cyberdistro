
## Cosa c'è in più rispetto a Sentinel Kiosk 0.1.1

Stesso sistema della Kiosk 0.1.1 (motori, regole, modello, Security Center), più:

- desktop **LXQt** su Xorg con gestore finestre **xfwm4**, accesso automatico (greetd + `startx`);
- barra in basso con menu, avvio rapido (Security Center, file manager, terminale, Firefox),
  finestre aperte, connessioni di rete (nm-tray), chiavette USB, orologio;
- **PCManFM-Qt** (file), **QTerminal** (terminale), **FeatherPad** (testo), **Firefox ESR** in italiano;
- tastiera italiana anche in X (`/etc/X11/xorg.conf.d/00-keyboard.conf`);
- il Security Center si apre all'avvio come finestra normale (non a schermo intero) e si riapre
  dall'icona con lo scudo nella barra;
- finestra Wi‑Fi del Security Center rifatta: dimensioni normali, pulsanti in italiano
  ("Connetti", "Annulla"), campo password solo per le reti protette, nessun simbolo emoji.

Spazio: +135 MB di pacchetti `.deb` (di cui ~70 MB Firefox), ISO finale 2 055 823 360 byte,
91 MB sotto il limite GitHub di 2 GiB per file.

## Verifica (7 novembre 2026)

ISO avviata **come chiavetta USB** (`usb-storage` in QEMU, 4 GB di RAM, 2 core):

| Modalità | Risultato |
| --- | --- |
| UEFI con Secure Boot (chiavi Microsoft) | ✅ menu GRUB, desktop LXQt, Security Center con stato VERDE |
| UEFI senza Secure Boot | ✅ come sopra |
| BIOS legacy | ✅ come sopra |

- Servizi `sentinel-engines`, `sentinel-sensor`, `sentinel-core` attivi; stato VERDE a riposo.
- Menu Start (Alt+F1) e lanciatore (Alt+F2) funzionanti e in italiano; Firefox, file manager e
  terminale si aprono.
- RAM usata con Security Center, Firefox e terminale aperti: ~1,46 GB su 4 GB.
- Difetti trovati e corretti durante le prove: schermo nero (live-config avviava una seconda
  sessione grafica su tty1, in conflitto con quella di greetd); icona del menu Start vuota
  (mancava il plugin SVG di Qt).

## Non ancora verificato
- Hardware reale e chiavetta fisica (solo macchine virtuali). La Kiosk 0.1.1 è stata avviata con
  successo su un portatile Dell, con Wi‑Fi funzionante.
- Navigazione con Firefox: si apre e mostra le pagine interne; le pagine web non sono state
  provate perché la rete della macchina virtuale di prova passa da un proxy che intercetta HTTPS.
- Schede grafiche NVIDIA recenti: Xorg usa il driver generico `modesetting` (nessun driver proprietario).
