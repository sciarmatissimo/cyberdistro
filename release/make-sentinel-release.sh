#!/usr/bin/env bash
# Release notes for CyberDistro Sentinel (Q3_K_M). Run after
#   editions/sentinel/build.sh --flavour <kiosk|lite>
# Usage: release/make-sentinel-release.sh [kiosk|lite]   (default kiosk)
# Does not touch PC Edition artifacts.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
FLAVOUR="${1:-kiosk}"
case "$FLAVOUR" in
    kiosk) NAME=Kiosk; VER="$(cat "$ROOT/editions/sentinel/VERSION")"; LIMIT_TXT="2 000 000 000 byte"
           EXTRA="$HERE/sentinel-verification-${VER}.md" ;;
    lite)  NAME=Lite;  VER="$(cat "$ROOT/editions/sentinel/flavours/lite/VERSION")"; LIMIT_TXT="2 147 483 648 byte = 2 GiB, limite GitHub per file"
           EXTRA="$HERE/sentinel-lite-verification-${VER}.md" ;;
    *) echo "flavour sconosciuto: $FLAVOUR" >&2; exit 2 ;;
esac
FILE="CyberDistro-Sentinel-${NAME}-Q3_K_M-x86_64.iso"
ISO="$ROOT/iso/$FILE"
[ -f "$ISO" ] || { echo "ISO non trovata: $ISO" >&2; exit 1; }
SIZE=$(stat -c%s "$ISO")
HASH=$(awk '{print $1}' "$ISO.sha256")
INFO="$(cat "$ROOT/iso/sentinel-${FLAVOUR}-build-info.txt" 2>/dev/null || true)"
NOTES="$HERE/RELEASE-NOTES-sentinel-${FLAVOUR}-${VER}.md"

if [ "$FLAVOUR" = lite ]; then
INTRO="Versione di Sentinel **con un desktop leggero (LXQt)**: stesso monitoraggio, stesso assistente AI e
stesso Security Center della versione Kiosk, più un normale desktop con menu, barra delle
applicazioni, file manager, terminale, editor di testo e Firefox."
SESSION="- Desktop **LXQt** (Xorg, gestore finestre xfwm4) in italiano: menu, barra, file manager PCManFM-Qt,
  terminale QTerminal, editor FeatherPad, rete dalla barra (nm-tray), **Firefox ESR**.
- Il Security Center si apre all'avvio come finestra normale e si riapre dall'icona nella barra."
else
INTRO="Versione di Sentinel **senza desktop**: all'avvio si apre solo il Security Center, a schermo
intero. È la versione più semplice da usare e la più leggera."
SESSION="- Sessione kiosk (labwc, Wayland): il Security Center è l'unica schermata. Nessun desktop,
  nessun browser."
fi

cat > "$NOTES" <<EOF
# CyberDistro Sentinel ${NAME} Q3_K_M ${VER}

${INTRO}

Edizione separata di CyberDistro per il **monitoraggio passivo della rete** con assistente AI
locale. Non sostituisce la PC Edition: le release precedenti restano invariate.

**File:** \`${FILE}\`
**Dimensione:** ${SIZE} byte (limite: ${LIMIT_TXT})
**SHA-256:** \`${HASH}\`

## Kiosk o Lite: quale scaricare
| | **Sentinel Kiosk** | **Sentinel Lite** |
| --- | --- | --- |
| Cosa vedi all'avvio | solo il Security Center, a schermo intero | un desktop LXQt con il Security Center aperto |
| Altre applicazioni | nessuna | file manager, terminale, editor, Firefox |
| Monitoraggio, AI locale, report | sì | sì, identici |
| Per chi | chi vuole solo controllare la rete, senza distrazioni | chi vuole anche navigare, salvare file o usare il terminale |
| RAM consigliata | 4 GB (8 GB con l'assistente AI) | 4 GB (8 GB con l'assistente AI) |
| Dove si scarica | release con tag \`sentinel-v*\` | release con tag \`sentinel-lite-v*\` |

Elenco di tutte le release: https://github.com/sciarmatissimo/cyberdistro/releases

## Cosa contiene
- Debian 13 live, avvio UEFI (anche con Secure Boot) e BIOS da chiavetta USB, persistenza LUKS2 opzionale.
${SESSION}
- Livello 1: Suricata 7 (regole Emerging Threats Open ridotte), Zeek 9.0 core, sensore passivo
  Sentinel (ARP, DHCP, mDNS, NDP). Nmap e arp-scan solo su consenso.
- Livello 2: sentinel-core, correlazione deterministica (scan, brute-force, ARP spoofing,
  DNS anomali, beaconing, esfiltrazione, movimento laterale, nuovi dispositivi) e stato
  verde/giallo/rosso/grigio.
- Livello 3: Qwen3.5-2B Q3_K_M (Apache-2.0) eseguito localmente con llama.cpp; spiega solo fatti
  verificati, ogni risposta passa un verificatore. Nessun cloud.
- Security Center Sentinel: Home, Rete, Protezione, Assistente AI, Report, Privacy, Impostazioni.
- Tor **non incluso**: si installa dalla sezione Privacy. Senza Tor la navigazione **non è anonima**.

## Come scrivere la chiavetta USB
La ISO va **scritta come immagine**, non copiata come file: copiare il file \`.iso\` su una
chiavetta già formattata non la rende avviabile.

- **Windows:** [Rufus](https://rufus.ie) → seleziona la ISO → quando chiede la modalità scegli
  **"Scrivi in modalità immagine DD"**. In alternativa [balenaEtcher](https://etcher.balena.io).
- **macOS / Linux:** balenaEtcher, oppure \`sudo dd if=${FILE} of=/dev/sdX bs=4M status=progress conv=fsync\`
  (sostituisci \`/dev/sdX\` con la chiavetta: tutto il suo contenuto viene cancellato).
- Avvio: inserisci la chiavetta, accendi il PC e apri il menu di avvio (di solito **F12**, F11,
  F10, F8 o Esc, a seconda del produttore), poi scegli la voce USB.
- **Secure Boot può restare attivo**: il caricatore è firmato (shim Debian firmato Microsoft +
  GRUB firmato Debian). Se il PC lo rifiuta comunque, verifica che nelle impostazioni del firmware
  sia consentito il "Microsoft UEFI CA" (certificati di terze parti; su alcuni portatili Lenovo e
  su alcuni PC "Secured-core" è disattivato per default).

## Credenziali live
Utente \`analyst\`, password \`cyberdistro\`.

## Verifica
\`\`\`bash
sha256sum -c ${FILE}.sha256
\`\`\`

## Componenti
\`\`\`
${INFO}
\`\`\`

Stato: **alpha**.
EOF
[ -f "$EXTRA" ] && cat "$EXTRA" >> "$NOTES"
echo "[release] $NOTES"
