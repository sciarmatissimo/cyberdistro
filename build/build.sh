#!/usr/bin/env bash
# CyberDistro — reproducible build entrypoint.
#
# Requirements (host):
#   - Debian 12/13 amd64 (or a Debian container with --privileged)
#   - packages: live-build, debootstrap, xorriso, squashfs-tools, mtools,
#     dosfstools, grub-pc-bin, grub-efi-amd64-bin, python3-pip, wget, gnupg
#   - root privileges (live-build mounts/chroots)
#   - network access to deb.debian.org, http.kali.org, dist.torproject.org
#   - ~25 GB free disk, ~2 GB RAM, and time (first build: tens of minutes)
#
# Output: ../iso/CyberDistro-PC-x86_64.iso  (+ .sha256)
#
# This script does NOT run in the restricted CI sandbox used during development
# (no mirror access, no privileged chroot). It is meant for a proper build host.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo 0.1.0)"
OUT="$ROOT/iso/CyberDistro-PC-x86_64.iso"

log(){ printf '\033[1;36m[build]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[build:ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (live-build needs chroot/mount)."
command -v lb >/dev/null || die "live-build not installed (apt-get install live-build)."

cd "$HERE"

# 1) Stage project sources into the chroot include tree so hooks can install them.
log "staging Security Center and privacy sources into chroot includes"
STAGE="config/includes.chroot/opt/cyberdistro-src"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -a "$ROOT/security-center" "$STAGE/"
cp -a "$ROOT/privacy"         "$STAGE/"
cp -a "$ROOT/forensics"       "$STAGE/"
# Also ship privacy ruleset at a stable runtime path.
install -D -m644 "$ROOT/privacy/nftables/killswitch.nft" \
    "config/includes.chroot/usr/share/cyberdistro/privacy/killswitch.nft"

# 2) Clean previous build state (keep caches unless --clean given).
if [ "${1:-}" = "--clean" ]; then
    log "lb clean --purge"
    lb clean --purge || true
fi

# 3) Configure + build.
log "lb config (Debian trixie amd64, UEFI+BIOS)"
lb config

log "lb build — this downloads packages and bakes the squashfs/ISO"
lb build 2>&1 | tee "build-$(date +%Y%m%d-%H%M%S).log"

# 4) Collect artifact.
SRC_ISO="$(ls -1 live-image-amd64.hybrid.iso 2>/dev/null || true)"
[ -n "$SRC_ISO" ] || die "live-build did not produce an ISO (see build log)."
mkdir -p "$ROOT/iso"
mv "$SRC_ISO" "$OUT"

# 5) Checksum.
( cd "$ROOT/iso" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
log "DONE → $OUT"
log "sha256 → $OUT.sha256"
cat "$OUT.sha256"
