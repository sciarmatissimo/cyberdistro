#!/usr/bin/env bash
# CyberDistro Sentinel (Q3_K_M) — build entrypoint.
#
# Run as root inside a Debian 13 (trixie) environment that allows chroot/mount,
# e.g.:  docker run --rm --privileged -v "$PWD":/work -w /work/editions/sentinel \
#            debian:trixie ./build.sh
#
# Steps (each verified, the build stops on any failure):
#   1. stage Sentinel + shared privacy sources into the chroot includes;
#   2. build the reduced Suricata rule set from Emerging Threats Open;
#   3. fetch the Zeek OBS signing key and check its fingerprint;
#   4. build llama.cpp (pinned commit, CPU-only, all x86-64 variants);
#   5. fetch Qwen3.5-2B Q3_K_M (pinned revision) and check its SHA-256;
#   6. lb config + lb build;
#   7. fail if the ISO is not below 2 000 000 000 bytes.
#
# Output: ../../iso/CyberDistro-Sentinel-Q3_K_M-x86_64.iso (+ .sha256)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VERSION="$(cat "$HERE/VERSION")"
OUT="$ROOT/iso/CyberDistro-Sentinel-Q3_K_M-x86_64.iso"
CACHE="${SENTINEL_CACHE:-$HERE/cache}"
LIMIT=2000000000

# Pinned inputs
LLAMA_COMMIT="29c720eaf72fcf8e4e61a56a88b994d92668261d"
MODEL_REPO="unsloth/Qwen3.5-2B-GGUF"
MODEL_REV="f6d5376be1edb4d416d56da11e5397a961aca8ae"
MODEL_FILE="Qwen3.5-2B-Q3_K_M.gguf"
MODEL_SHA256="8b049f98461020b7e15797e13413fc63b9b500ffa883c74618b618ecbc2bfccf"
ZEEK_KEY_FPR="F9FA0223B56B116C363737EF5DA57BDD6DD785CA"
ET_URL="https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz"

log(){ printf '\033[1;36m[sentinel]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[sentinel:ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (live-build needs chroot/mount)."
for c in lb wget gpg python3 cmake g++ git sha256sum xorriso mdir; do
    command -v "$c" >/dev/null || die "missing tool: $c"
done
mkdir -p "$CACHE"
cd "$HERE"
INC="config/includes.chroot"

# 1) sources ---------------------------------------------------------------
log "staging Sentinel and privacy sources"
rm -rf "$INC/opt/cyberdistro-src"
mkdir -p "$INC/opt/cyberdistro-src"
cp -a "$ROOT/sentinel" "$INC/opt/cyberdistro-src/sentinel"
rm -rf "$INC/opt/cyberdistro-src/sentinel/tests" "$INC/opt/cyberdistro-src/sentinel/build"
cp -a "$ROOT/privacy" "$INC/opt/cyberdistro-src/privacy"

# 2) Suricata rules ----------------------------------------------------------
log "building the reduced Suricata rule set (ET Open)"
wget -q -O "$CACHE/emerging.rules.tar.gz" "$ET_URL"
ET_VERSION="$(wget -q -O - "${ET_URL%/*}/version.txt" || echo unknown)"
mkdir -p "$INC/etc/suricata/rules"
python3 "$HERE/rules/build-ruleset.py" "$CACHE/emerging.rules.tar.gz" \
    "$INC/etc/suricata/rules/sentinel.rules" "$HERE/rules/disable.txt"
echo "ET Open version ${ET_VERSION} ($(date -u +%F))" > "$INC/etc/suricata/rules/SENTINEL-RULES-VERSION"

# 3) Zeek archive key --------------------------------------------------------
log "fetching and verifying the Zeek OBS key"
wget -q -O "$CACHE/zeek.key" https://download.opensuse.org/repositories/security:/zeek/Debian_13/Release.key
fpr="$(gpg --show-keys --with-colons "$CACHE/zeek.key" | awk -F: '/^fpr:/{print $10; exit}')"
[ "$fpr" = "$ZEEK_KEY_FPR" ] || die "Zeek key fingerprint mismatch: got '$fpr'"
install -m644 "$CACHE/zeek.key" config/archives/zeek.key.chroot

# 4) llama.cpp -----------------------------------------------------------------
LL="$CACHE/llama-$LLAMA_COMMIT"
if [ ! -x "$LL/out/llama-server" ]; then
    log "building llama.cpp $LLAMA_COMMIT (CPU only, portable)"
    rm -rf "$LL"
    git init -q "$LL/src"
    git -C "$LL/src" fetch -q --depth 1 https://github.com/ggml-org/llama.cpp "$LLAMA_COMMIT"
    git -C "$LL/src" checkout -q FETCH_HEAD
    cmake -S "$LL/src" -B "$LL/build" -DCMAKE_BUILD_TYPE=Release \
        -DGGML_NATIVE=OFF -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=ON \
        -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
        -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_RPATH='$ORIGIN' -DCMAKE_INSTALL_RPATH='$ORIGIN' >/dev/null
    cmake --build "$LL/build" -j"$(nproc)" --target llama-server >/dev/null
    mkdir -p "$LL/out"
    cp -a "$LL/build/bin/llama-server" "$LL"/build/bin/*.so* "$LL/out/"
    strip --strip-unneeded "$LL"/out/* 2>/dev/null || true
fi
rm -rf "$INC/opt/cyberdistro/llama"
mkdir -p "$INC/opt/cyberdistro/llama"
cp -a "$LL"/out/* "$INC/opt/cyberdistro/llama/"
echo "$LLAMA_COMMIT" > "$INC/opt/cyberdistro/llama/LLAMA-CPP-COMMIT"

# 5) model -----------------------------------------------------------------------
M="$CACHE/$MODEL_FILE"
if [ ! -f "$M" ] || ! echo "$MODEL_SHA256  $M" | sha256sum -c --status; then
    log "downloading $MODEL_FILE ($MODEL_REPO@$MODEL_REV)"
    wget -q -O "$M" "https://huggingface.co/$MODEL_REPO/resolve/$MODEL_REV/$MODEL_FILE"
fi
echo "$MODEL_SHA256  $M" | sha256sum -c - || die "model checksum mismatch"
mkdir -p "$INC/opt/cyberdistro/models"
ln -f "$M" "$INC/opt/cyberdistro/models/$MODEL_FILE" 2>/dev/null || cp -f "$M" "$INC/opt/cyberdistro/models/$MODEL_FILE"
echo "$MODEL_SHA256  /opt/cyberdistro/models/$MODEL_FILE" > "$INC/opt/cyberdistro/models/SHA256SUMS"
cat > "$INC/opt/cyberdistro/models/MODEL-INFO" <<EOF
model: Qwen3.5-2B (Qwen team), GGUF quantization Q3_K_M by Unsloth
source: https://huggingface.co/$MODEL_REPO (revision $MODEL_REV)
license: Apache-2.0
sha256: $MODEL_SHA256
EOF

# 6) GRUB font -----------------------------------------------------------------------
# BIOS GRUB loads $prefix/fonts/unicode.pf2 for the graphical menu; without it the
# menu is invisible and an error is printed ("unicode.pf2 not found").
install -D -m644 /usr/share/grub/unicode.pf2 config/includes.binary/boot/grub/fonts/unicode.pf2

# 7) live-build --------------------------------------------------------------------
if [ "${1:-}" = "--clean" ]; then lb clean --purge || true; fi
log "lb config"
lb config
log "lb build (tens of minutes)"
lb build 2>&1 | tee "$CACHE/build-$(date +%Y%m%d-%H%M%S).log"
[ -f live-image-amd64.hybrid.iso ] || die "live-build did not produce an ISO (see log in $CACHE)"
mkdir -p "$ROOT/iso"
mv live-image-amd64.hybrid.iso "$OUT"

# 8) boot checks ----------------------------------------------------------------------
# UEFI must boot through the signed shim (Secure Boot); BIOS GRUB must find its font.
EFIIMG="$CACHE/efi.img"
rm -f "$EFIIMG"
xorriso -osirrox on -indev "$OUT" -extract /boot/grub/efi.img "$EFIIMG" >/dev/null 2>&1 || die "no /boot/grub/efi.img in the ISO"
# bootx64.efi = shim (signed by Microsoft UEFI CA), grubx64.efi = GRUB signed by Debian.
for f in /EFI/boot/bootx64.efi /EFI/boot/grubx64.efi; do
    mdir -i "$EFIIMG" "::$f" >/dev/null 2>&1 || die "Secure Boot chain incomplete: $f missing in efi.img"
done
xorriso -indev "$OUT" -find /boot/grub/fonts/unicode.pf2 2>/dev/null | grep -q unicode.pf2 || die "GRUB font missing in the ISO"
log "boot checks OK (shim + signed GRUB in efi.img, GRUB font present)"

# 9) size gate -----------------------------------------------------------------------
SIZE="$(stat -c%s "$OUT")"
log "ISO size: $SIZE bytes (limit $LIMIT)"
[ "$SIZE" -lt "$LIMIT" ] || die "ISO exceeds the 2 000 MB limit: $SIZE bytes"
( cd "$ROOT/iso" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
cat > "$ROOT/iso/sentinel-build-info.txt" <<EOF
edition: CyberDistro Sentinel Q3_K_M
version: $VERSION
iso_bytes: $SIZE
llama_cpp: $LLAMA_COMMIT
model: $MODEL_REPO@$MODEL_REV/$MODEL_FILE sha256=$MODEL_SHA256
suricata_rules: ET Open $ET_VERSION
built_at: $(date -u +%FT%TZ)
EOF
log "DONE → $OUT"
cat "$OUT.sha256"
