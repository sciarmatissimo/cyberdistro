#!/usr/bin/env bash
# DNS-leak check. In Tor/Hardened mode, DNS must resolve only via Tor's local
# DNSPort (127.0.0.1); clear-text DNS to the outside must be dropped.
set -uo pipefail
fail(){ echo "FAIL: $*"; exit 1; }
ok(){ echo "OK: $*"; }

echo "== DNS-leak verification =="

# 1) Configured resolvers should be local (127.0.0.1) in Tor/Hardened mode.
resolvers="$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null)"
echo "   resolver configurati: ${resolvers:-<nessuno>}"
if nft list table inet cyberdistro_killswitch >/dev/null 2>&1; then
    nonlocal="$(echo "$resolvers" | grep -v '^127\.' || true)"
    [ -z "$nonlocal" ] && ok "solo resolver locali (atteso in modalità Tor)" \
        || fail "resolver NON locali presenti: $nonlocal (possibile leak)"
fi

# 2) Direct UDP/53 to a public resolver must FAIL when the kill-switch is active.
if nft list table inet cyberdistro_killswitch >/dev/null 2>&1; then
    if command -v dig >/dev/null; then
        if dig +time=3 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1; then
            fail "DNS diretto a 1.1.1.1 riuscito (LEAK!)"
        else
            ok "DNS diretto esterno bloccato (atteso)"
        fi
    fi
fi
echo "== done =="
