
## Cosa è stato verificato (2–3 novembre 2026)

Le verifiche sotto sono state eseguite su una build locale dello **stesso commit e della stessa
configurazione** (1 889 988 608 byte, SHA-256 `006db05bb6ad163d8580e296e60993fa3ffa0e9ba0e56ea9ecc72ab3ae7ff2fb`).
La ISO allegata a questa release è ricostruita da GitHub Actions dallo stesso sorgente: non è
identica byte per byte (data di build e versione giornaliera delle regole ET Open, riportata in
`sentinel-build-info.txt`), quindi il suo SHA-256 è quello indicato in testa a queste note.

| Verifica | Esito | Come |
| --- | --- | --- |
| Dimensione sotto 2 000 MB | ✅ 1 889 988 608 byte | Controllo automatico nella build |
| Avvio BIOS legacy fino all'interfaccia | ✅ | QEMU (SeaBIOS, `-cpu max`, 6 GB), circa 10 minuti in emulazione software |
| Avvio UEFI fino all'interfaccia | ✅ | QEMU (OVMF, `-cpu max`, 4 GB) |
| Suricata, Zeek, sensore e sentinel-core attivi all'avvio | ✅ stato VERDE, "monitoraggio attivo" | Stessi test QEMU, `systemctl status` |
| Port scan reale rilevato sulla ISO avviata | ✅ "Qualcuno sta esplorando le porte", confermato, gravità alta, stato ROSSO | 30 connessioni dall'host verso la VM |
| RAM reale del sistema avviato | ✅ 1 049 MB usati in totale; Suricata + Zeek 596 MB; sentinel-core 14 MB; sensore 13 MB | `free -m`, `systemctl status` nella VM |
| Assistente AI con il runtime e il modello della ISO | ✅ 25–48 s per spiegazione su 2 core; 2 risposte accettate e 1 scartata dal verificatore su 3 | squashfs della ISO eseguita in chroot su CPU reale |
| Correlazione su sei scenari d'attacco sintetici | ✅ 7 regole su 7 | 28 test unitari (`sentinel/tests`) |
| Falsi positivi su traffico LAN normale (IPv6, mDNS, DHCP, SSDP, NTP…) | ✅ 0 avvisi dopo aver disattivato SID 2030387 | `tests/make_benign_pcap.py` + Suricata |
| Interfaccia: 7 sezioni senza errori | ✅ | Smoke test offscreen + VM |

## Problemi trovati dai test e già corretti in questa ISO
- La regola ET 2030387 (Ripple20, CVE-2020-11899) scattava sul normale traffico IPv6 multicast e
  rendeva lo stato ROSSO senza alcun attacco: disattivata.
- Su una CPU virtuale senza SSSE3 (QEMU `qemu64`) Suricata non partiva e lo stato restava
  GRIGIO. Con una CPU completa funziona. Requisito: CPU x86-64 con SSSE3 (Intel Core 2 o
  successivi, AMD Bulldozer o successivi).
- Il menu di avvio restava fermo: ora parte da solo dopo 5 secondi.

## Non ancora verificato
- **Hardware reale** (solo macchine virtuali), Wi-Fi reale, chiavetta USB fisica.
- Assistente AI dentro la VM: in emulazione software va in timeout (480 s) e l'interfaccia mostra
  correttamente la scheda scritta a mano; su CPU reale funziona (vedi tabella).
- Installazione di Tor e Tor Browser dalla sezione Privacy (richiede rete reale): i comandi sono
  scritti ma non eseguiti end-to-end.
- Persistenza cifrata su questa edizione, azioni di blocco nftables in un sistema avviato,
  esportazione del report su chiavetta.
- Soglie di correlazione su reti reali (falsi positivi oltre a quelli sopra).

## Limiti noti
- Vede solo il traffico che arriva a questo PC: su reti commutate non vede il traffico tra altri dispositivi.
- L'assistente spesso ripete la scheda invece di semplificarla; quando aggiunge fatti non presenti
  nelle prove, il verificatore scarta la risposta (nei test circa metà delle risposte).
- Nel firmware incluso restano piccoli file per schede di rete da server (es. Chelsio `cxgb4`) che
  fanno parte del pacchetto `firmware-misc-nonfree`; i pacchetti di firmware da datacenter sono esclusi.
- `firmware-ipw2x00` (Wi-Fi Intel del 2003) escluso: richiede l'accettazione interattiva di una licenza.
