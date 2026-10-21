#!/usr/bin/env bash
# Repo-wide test runner. Runs everything that can run on a dev host WITHOUT a
# built ISO: Security Center unit tests, shell syntax checks, nft syntax check,
# and SBOM generation. Writes results under tests/results/.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
fail=0

echo "============================================================"
echo "CyberDistro test suite — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

echo "[1/4] Security Center unit tests"
( cd "$ROOT/security-center" && PYTHONPATH=src python3 -m unittest discover -s tests ) \
    && echo "  PASS" || { echo "  FAIL"; fail=1; }

echo "[2/4] Shell script syntax (bash -n)"
for f in "$ROOT"/privacy/bin/privacy-mode "$ROOT"/privacy/tests/*.sh \
         "$ROOT"/privacy/persistence/*.sh "$ROOT"/build/build.sh \
         "$ROOT"/release/*.sh; do
    bash -n "$f" && echo "  OK   ${f#$ROOT/}" || { echo "  FAIL ${f#$ROOT/}"; fail=1; }
done

echo "[3/4] nftables kill-switch syntax (nft -c)"
if command -v nft >/dev/null; then
    sed 's/@TOR_UID@/123/g' "$ROOT/privacy/nftables/killswitch.nft" > /tmp/ks.nft
    nft -c -f /tmp/ks.nft && echo "  OK" || { echo "  FAIL"; fail=1; }
else
    echo "  SKIP (nft non disponibile)"
fi

echo "[4/4] SBOM generation"
python3 "$ROOT/sbom/generate-sbom.py" > "$ROOT/sbom/cyberdistro.cdx.json" \
    && echo "  OK ($(python3 -c "import json;print(len(json.load(open('$ROOT/sbom/cyberdistro.cdx.json'))['components']))") componenti)" \
    || { echo "  FAIL"; fail=1; }

echo "============================================================"
[ "$fail" -eq 0 ] && echo "RISULTATO: TUTTO OK" || echo "RISULTATO: ALCUNI TEST FALLITI"
exit "$fail"
