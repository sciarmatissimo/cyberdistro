#!/usr/bin/env bash
# Release notes for CyberDistro Sentinel (Q3_K_M). Run after editions/sentinel/build.sh.
# Does not touch PC Edition artifacts.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VER="$(cat "$ROOT/editions/sentinel/VERSION")"
ISO="$ROOT/iso/CyberDistro-Sentinel-Q3_K_M-x86_64.iso"
[ -f "$ISO" ] || { echo "ISO non trovata: $ISO" >&2; exit 1; }
SIZE=$(stat -c%s "$ISO")
HASH=$(awk '{print $1}' "$ISO.sha256")
INFO="$(cat "$ROOT/iso/sentinel-build-info.txt" 2>/dev/null || true)"
NOTES="$HERE/RELEASE-NOTES-sentinel-${VER}.md"
EXTRA="$HERE/sentinel-verification-${VER}.md"

cat > "$NOTES" <<EOF
# CyberDistro Sentinel Q3_K_M ${VER}

Edizione separata di CyberDistro per il **monitoraggio passivo della rete** con assistente AI
locale. Non sostituisce la PC Edition: le release precedenti restano invariate.

**File:** \`CyberDistro-Sentinel-Q3_K_M-x86_64.iso\`
**Dimensione:** ${SIZE} byte (limite del progetto: 2 000 000 000)
**SHA-256:** \`${HASH}\`

## Cosa contiene
- Debian 13 live, avvio UEFI e BIOS da chiavetta USB, persistenza LUKS2 opzionale.
- Livello 1: Suricata 7 (regole Emerging Threats Open ridotte), Zeek 9.0 core, sensore passivo
  Sentinel (ARP, DHCP, mDNS, NDP). Nmap e arp-scan solo su consenso.
- Livello 2: sentinel-core, correlazione deterministica (scan, brute-force, ARP spoofing,
  DNS anomali, beaconing, esfiltrazione, movimento laterale, nuovi dispositivi) e stato
  verde/giallo/rosso/grigio.
- Livello 3: Qwen3.5-2B Q3_K_M (Apache-2.0) eseguito localmente con llama.cpp; spiega solo fatti
  verificati, ogni risposta passa un verificatore. Nessun cloud.
- Security Center Sentinel: Home, Rete, Protezione, Assistente AI, Report, Privacy, Impostazioni.
- Tor **non incluso**: si installa dalla sezione Privacy.

## Credenziali live
Utente \`analyst\`, password \`cyberdistro\`.

## Verifica
\`\`\`bash
sha256sum -c CyberDistro-Sentinel-Q3_K_M-x86_64.iso.sha256
\`\`\`

## Componenti
\`\`\`
${INFO}
\`\`\`

Stato: **alpha**. Secure Boot non firmato (disattivalo per avviare).
EOF
[ -f "$EXTRA" ] && cat "$EXTRA" >> "$NOTES"
echo "[release] $NOTES"
