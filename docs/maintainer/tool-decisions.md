# Decisioni sugli strumenti (inclusione / esclusione)

Criteri: legittimità d'uso difensivo/autorizzato, licenza redistribuibile,
packaging sostenibile, valore reale (non "numero di tool"). Le scansioni e le
operazioni invasive sono sempre dietro gating di autorizzazione.

| Strumento | Decisione | Motivazione |
|---|---|---|
| Nmap, Wireshark, tcpdump, Zeek | inclusi | Standard, licenze OK, wrapper/uso diretto |
| OWASP ZAP | incluso | Apache-2.0; scansione web guidata |
| Burp Suite Community | **non incluso** → installazione opzionale guidata | Licenza proprietaria PortSwigger: redistribuzione non garantita |
| The Sleuth Kit, Autopsy | inclusi | Forense standard, licenze OK |
| Volatility 3 | incluso via pip (pinned) | Packaging Debian in ritardo; licenza consente |
| YARA | incluso | Regole malware, BSD |
| Ghidra, radare2/rizin, GDB, binwalk | inclusi | RE statico, licenze OK |
| Detect It Easy | valutato, non ancora incluso | Packaging/licenza da verificare caso per caso |
| John the Ripper, hashcat | inclusi | Audit credenziali **autorizzati**; dietro gating e avvisi |
| aircrack-ng, reaver | inclusi | Wireless; capacità hardware rilevate a runtime, nessuna promessa |
| Tor + Tor Browser | inclusi | Privacy centrale; Tor Browser **ufficiale non modificato** |
| Metasploit e framework di exploitation | **non inclusi di default in alpha** | Scelta prudente: la priorità del progetto è assessment/forense/privacy con uso responsabile; valutazione separata con gating rafforzato prima di un'eventuale inclusione |
| Strumenti puramente offensivi/payload pre-confezionati | esclusi | Fuori dallo scopo "safe by default"; nessun automatismo d'attacco |

Nota: l'esclusione di default di alcuni framework non è un giudizio tecnico ma
una scelta di prodotto per l'alpha (responsabilità, superficie, aspettative
utente). L'inclusione futura passa da una valutazione di sicurezza e da gating
dedicato, coerente con §11 del capitolato.
