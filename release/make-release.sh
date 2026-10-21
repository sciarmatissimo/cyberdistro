#!/usr/bin/env bash
# Produce release artifacts for a built ISO: SHA-256, a manifest, and notes.
# Run AFTER build/build.sh has produced ../iso/CyberDistro-PC-x86_64.iso.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
ISO="$ROOT/iso/CyberDistro-PC-x86_64.iso"

[ -f "$ISO" ] || { echo "ISO non trovata: $ISO — esegui prima build/build.sh" >&2; exit 1; }

echo "[release] calcolo SHA-256"
( cd "$ROOT/iso" && sha256sum "$(basename "$ISO")" | tee "$(basename "$ISO").sha256" )

SIZE=$(stat -c%s "$ISO")
HASH=$(awk '{print $1}' "$ISO.sha256")

echo "[release] genero manifest"
cat > "$HERE/manifest-${VERSION}.json" <<EOF
{
  "name": "CyberDistro",
  "edition": "PC-x86_64",
  "version": "${VERSION}",
  "iso_file": "$(basename "$ISO")",
  "size_bytes": ${SIZE},
  "sha256": "${HASH}",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "base": "Debian trixie + Kali tools (APT pinning)",
  "boot": ["UEFI", "BIOS-legacy (isohybrid)"],
  "secure_boot": "not signed (alpha) — disable Secure Boot to boot",
  "sbom": "sbom/cyberdistro.cdx.json"
}
EOF

echo "[release] genero note di rilascio"
cat > "$HERE/RELEASE-NOTES-${VERSION}.md" <<EOF
# CyberDistro ${VERSION} — Release notes

**SHA-256:** \`${HASH}\`
**Dimensione:** ${SIZE} byte

## Verifica integrità
\`\`\`bash
cd iso
sha256sum -c CyberDistro-PC-x86_64.iso.sha256
\`\`\`
Confronta l'hash con quello pubblicato qui sopra e, quando disponibile, con la
firma GPG del progetto.

## Stato
Release **ALPHA**. Vedi \`docs/architecture/03-status.md\` per funzionalità
verificate, non verificate e limitazioni note. Secure Boot non firmato.
EOF

echo "[release] fatto:"
echo "  $HERE/manifest-${VERSION}.json"
echo "  $HERE/RELEASE-NOTES-${VERSION}.md"
echo "  $ISO.sha256"
