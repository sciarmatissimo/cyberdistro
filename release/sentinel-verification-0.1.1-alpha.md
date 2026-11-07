
## Cosa cambia rispetto alla 0.1.0

**Correzione: la chiavetta non veniva riconosciuta all'avvio sui PC con Secure Boot attivo**
(la grande maggioranza dei PC con Windows 10/11). Il caricatore UEFI della 0.1.0 non era firmato e
il firmware lo rifiutava ("Access Denied", "No bootable option or device was found").

- Avvio UEFI tramite la catena firmata di Debian: `bootx64.efi` = shim firmato da Microsoft
  (UEFI CA 2011), `grubx64.efi` = GRUB firmato da Debian, kernel firmato da Debian.
- In avvio BIOS il menu di GRUB ora si vede (prima mancava il font `unicode.pf2` e compariva un errore).
- La build fallisce automaticamente se nella ISO mancano lo shim, il GRUB firmato o il font.
- Contenuto e funzioni del sistema invariati rispetto alla 0.1.0.

## Verifica (7 novembre 2026)

ISO avviata **come chiavetta USB** (dispositivo `usb-storage` in QEMU), non come CD:

| Modalità | 0.1.0 | 0.1.1 |
| --- | --- | --- |
| UEFI con Secure Boot (chiavi Microsoft) | ❌ rifiutata: "Access Denied" | ✅ menu GRUB, interfaccia, stato VERDE |
| UEFI senza Secure Boot | ✅ | ✅ |
| BIOS legacy | ⚠️ si avvia, menu invisibile ed errore font | ✅ menu visibile, interfaccia |

Le prove della 0.1.0 su motori, rilevamento del port scan e assistente AI restano valide: il sistema
installato nella ISO è lo stesso.

## Non ancora verificato
- Hardware reale e chiavetta fisica (solo macchine virtuali).
- PC che hanno disattivato i certificati Microsoft di terze parti ("Microsoft UEFI CA") nel firmware:
  lì serve abilitarli o disattivare Secure Boot.
