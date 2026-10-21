#!/usr/bin/env bash
# Verify a downloaded CyberDistro ISO against its published SHA-256.
set -euo pipefail
ISO="${1:-CyberDistro-PC-x86_64.iso}"
SUM="${2:-${ISO}.sha256}"
[ -f "$ISO" ] || { echo "ISO non trovata: $ISO" >&2; exit 1; }
[ -f "$SUM" ] || { echo "File checksum non trovato: $SUM" >&2; exit 1; }
echo "Verifico $ISO contro $SUM ..."
if sha256sum -c "$SUM"; then
    echo "OK: integrità verificata."
else
    echo "ATTENZIONE: l'hash NON corrisponde. Non usare questa immagine." >&2
    exit 1
fi
