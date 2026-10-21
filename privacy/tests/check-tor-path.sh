#!/usr/bin/env bash
# Verify that traffic actually goes through Tor, and that there is NO direct
# fallback. Run on the live system. Exit non-zero if the check fails.
#
# Method:
#   1) Confirm a Tor SOCKS port is listening.
#   2) Ask the Tor Project's check service THROUGH Tor; expect IsTor=true.
#   3) With the kill-switch loaded, confirm a DIRECT (non-Tor) request FAILS
#      (fail-closed): a direct curl must not succeed.
set -uo pipefail

SOCKS="${TOR_SOCKS:-127.0.0.1:9050}"
fail(){ echo "FAIL: $*"; exit 1; }
ok(){ echo "OK: $*"; }

echo "== Tor path verification =="

# 1) SOCKS port present?
if command -v ss >/dev/null; then
    ss -ltn 2>/dev/null | grep -qE "127\.0\.0\.1:(9050|9150)" \
        && ok "SOCKS port in ascolto" || fail "nessuna porta SOCKS Tor (9050/9150)"
fi

# 2) Through Tor: expect IsTor:true
if command -v curl >/dev/null; then
    resp="$(curl -s --socks5-hostname "$SOCKS" https://check.torproject.org/api/ip || true)"
    echo "   risposta check.torproject.org (via Tor): ${resp:-<vuota>}"
    echo "$resp" | grep -q '"IsTor":true' \
        && ok "il traffico esce da Tor (IsTor=true)" \
        || fail "check.torproject.org non conferma Tor"
fi

# 3) Fail-closed: a DIRECT request must NOT succeed when kill-switch is active.
if nft list table inet cyberdistro_killswitch >/dev/null 2>&1; then
    if curl -s --max-time 8 --interface "$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')" \
            https://example.com -o /dev/null 2>/dev/null; then
        fail "richiesta DIRETTA riuscita con kill-switch attivo (LEAK!)"
    else
        ok "richiesta diretta bloccata (fail-closed confermato)"
    fi
else
    echo "NOTE: kill-switch non attivo; salto il test fail-closed."
fi
echo "== done =="
