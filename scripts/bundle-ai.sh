#!/usr/bin/env bash
# bundle-ai.sh — stage a local LLM (llama.cpp runtime + a small GGUF model) into
# a live-build chroot include tree, so the edition ships a fully conversational,
# 100%-local AI assistant out of the box (no cloud, no account).
#
# The runtime/model land at /opt/cyberdistro/{llama,models} — exactly where
# cyberdistro_sc.tools.localmodel looks — so the Security Center assistant starts
# the model on demand with a RAM safety gate.
#
#   scripts/bundle-ai.sh <INCLUDES_CHROOT_DIR> [CACHE_DIR]
#
# Honest by design: the model is pinned to a repository revision AND a content
# SHA-256, and the script FAILS CLOSED if the checksum is missing or does not
# match — it never ships an unverified blob. Override the pinned inputs with the
# CYBERDISTRO_AI_* / CYBERDISTRO_LLAMA_COMMIT environment variables.
#
# Default model: Qwen2.5-0.5B-Instruct (Apache-2.0), Q4_K_M GGUF (~468 MiB) —
# chosen so the PC Edition ISO stays within GitHub's 2 GiB per-asset release
# limit (verify at build time; see the size note in build/build.sh). Requires
# a build host with: git, cmake, a C/C++ toolchain, wget and ~2 GB RAM.
set -euo pipefail

INC="${1:-}"
[ -n "$INC" ] || { echo "usage: $0 <includes.chroot dir> [cache dir]" >&2; exit 2; }
CACHE="${2:-${CYBERDISTRO_AI_CACHE:-$(cd "$(dirname "$0")/.." && pwd)/.cache/ai}}"
mkdir -p "$CACHE"

log(){ printf '\033[1;35m[bundle-ai]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[bundle-ai:ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

# Pinned inputs (overridable). Defaults verified against Hugging Face.
LLAMA_COMMIT="${CYBERDISTRO_LLAMA_COMMIT:-29c720eaf72fcf8e4e61a56a88b994d92668261d}"
MODEL_REPO="${CYBERDISTRO_AI_MODEL_REPO:-Qwen/Qwen2.5-0.5B-Instruct-GGUF}"
MODEL_REV="${CYBERDISTRO_AI_MODEL_REV:-9217f5db79a29953eb74d5343926648285ec7e67}"
MODEL_FILE="${CYBERDISTRO_AI_MODEL_FILE:-qwen2.5-0.5b-instruct-q4_k_m.gguf}"
MODEL_SHA256="${CYBERDISTRO_AI_MODEL_SHA256:-74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db}"
MODEL_LICENSE="${CYBERDISTRO_AI_MODEL_LICENSE:-Apache-2.0}"

[ -n "$MODEL_SHA256" ] || die "no model SHA-256 pinned (set CYBERDISTRO_AI_MODEL_SHA256); refusing to ship an unverified model."
for t in git cmake wget sha256sum; do command -v "$t" >/dev/null || die "missing build tool: $t"; done

# 1) llama.cpp (CPU-only, portable across x86-64 variants, shared libs w/ $ORIGIN rpath)
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

# 2) model (pinned revision + verified content hash; fail closed on mismatch)
M="$CACHE/$MODEL_FILE"
if [ ! -f "$M" ] || ! echo "$MODEL_SHA256  $M" | sha256sum -c --status; then
    log "downloading $MODEL_FILE ($MODEL_REPO@$MODEL_REV)"
    wget -q -O "$M" "https://huggingface.co/$MODEL_REPO/resolve/$MODEL_REV/$MODEL_FILE" \
        || die "model download failed"
fi
echo "$MODEL_SHA256  $M" | sha256sum -c - >/dev/null || die "model checksum mismatch — refusing to bundle."
mkdir -p "$INC/opt/cyberdistro/models"
ln -f "$M" "$INC/opt/cyberdistro/models/$MODEL_FILE" 2>/dev/null \
    || cp -f "$M" "$INC/opt/cyberdistro/models/$MODEL_FILE"
echo "$MODEL_SHA256  /opt/cyberdistro/models/$MODEL_FILE" > "$INC/opt/cyberdistro/models/SHA256SUMS"
cat > "$INC/opt/cyberdistro/models/MODEL-INFO" <<EOF
model: $MODEL_FILE
source: https://huggingface.co/$MODEL_REPO (revision $MODEL_REV)
license: $MODEL_LICENSE
sha256: $MODEL_SHA256
note: local-only; served on 127.0.0.1 on demand by the Security Center assistant.
EOF

SZ_MODEL=$(stat -c%s "$INC/opt/cyberdistro/models/$MODEL_FILE" 2>/dev/null || echo 0)
SZ_LLAMA=$(du -sb "$INC/opt/cyberdistro/llama" 2>/dev/null | cut -f1 || echo 0)
log "staged AI: model $((SZ_MODEL/1024/1024)) MiB + runtime $((SZ_LLAMA/1024/1024)) MiB → $INC/opt/cyberdistro"
log "OK (remember: the ISO must stay < 2 GiB for a GitHub release asset)"
