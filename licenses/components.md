# Inventario licenze (sintesi leggibile)

> Fonte autorevole e completa: `sbom/cyberdistro.cdx.json`. Questa tabella è una
> sintesi delle licenze note dei componenti principali. Le **versioni** sono
> fissate alla build dal gestore pacchetti (apt/dpkg); qui non sono inventate.

| Componente | Categoria | Licenza (nota) | Redistribuibile in ISO |
|---|---|---|---|
| cyberdistro-security-center | first-party | GPL-3.0-or-later | sì |
| nmap | network | NPSL | sì |
| wireshark / tshark | network | GPL-2.0-or-later | sì |
| tcpdump | network | BSD-3-Clause | sì |
| zeek | network | BSD-3-Clause | sì |
| OWASP ZAP (zaproxy) | web | Apache-2.0 | sì |
| nikto | web | GPL-2.0-only | sì |
| **Burp Suite Community** | web | Proprietaria (PortSwigger) | **no → install. opzionale guidata** |
| The Sleuth Kit | forensics | GPL-2.0-or-later / CPL-1.0 | sì |
| Autopsy | forensics | Apache-2.0 | sì |
| Volatility 3 | forensics | VSL (custom) | sì (via pip, pinned) |
| YARA | forensics/RE | BSD-3-Clause | sì |
| Ghidra | reversing | Apache-2.0 | sì |
| radare2 / rizin / Cutter | reversing | LGPL-3.0 | sì |
| GDB | reversing | GPL-3.0-or-later | sì |
| binwalk | reversing | MIT | sì |
| John the Ripper | crypto | GPL-2.0-or-later | sì |
| hashcat | crypto | MIT | sì |
| OpenSSL | crypto | Apache-2.0 | sì |
| aircrack-ng | wireless | GPL-2.0-or-later | sì |
| Tor / torsocks | privacy | BSD-3-Clause / GPL-2.0 | sì |
| **Tor Browser** | privacy | MPL-2.0 / Tor Project | sì (build ufficiale, non modificata) |
| KDE Plasma | desktop | GPL-2.0-or-later / LGPL | sì |

**Detect It Easy** e altri strumenti valutati ma non ancora inclusi sono elencati
in `docs/maintainer/tool-decisions.md` con la motivazione (licenza/packaging).
