#!/bin/sh
# CyberDistro — ensure the live user is usable at first boot.
# live-config creates the live user (default: analyst) early in boot, usually
# passwordless. Autologin does not need a password, but sudo/polkit do, so we
# set a KNOWN default password and make sure the account is unlocked and in the
# sudo group. Best-effort: never blocks boot.
#
# Default credentials (DOCUMENTED, change after first boot if persisting):
#   user: analyst   password: cyberdistro
set -u

U="${CYBERDISTRO_LIVE_USER:-analyst}"

# Wait briefly for live-config to create the user (up to ~20s).
i=0
while [ $i -lt 20 ]; do
    if id "$U" >/dev/null 2>&1; then break; fi
    sleep 1; i=$((i+1))
done

if id "$U" >/dev/null 2>&1; then
    echo "${U}:cyberdistro" | chpasswd 2>/dev/null || true
    passwd -u "$U" 2>/dev/null || true
    # Ensure sudo access (group name is 'sudo' on Debian).
    getent group sudo >/dev/null 2>&1 && usermod -aG sudo "$U" 2>/dev/null || true
fi
exit 0
