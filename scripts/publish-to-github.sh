#!/usr/bin/env bash
# publish-to-github.sh — pubblica CyberDistro su GitHub da riga di comando.
#
# Fa, in modo sicuro e con conferme, quello che faresti a mano:
#   1) inizializza il repository git locale (se non lo è già);
#   2) collega il tuo repository remoto su GitHub;
#   3) crea un commit con tutti i file del progetto;
#   4) invia (push) tutto su GitHub;
#   5) (opzionale) crea e invia un TAG di versione, che fa partire da solo il
#      workflow "Build ISO" e pubblica la Release con ISO + checksum + SBOM.
#
# USO:
#   ./scripts/publish-to-github.sh <URL-del-tuo-repo> [vX.Y.Z]
#
# ESEMPI:
#   # solo caricare il codice (nessuna Release):
#   ./scripts/publish-to-github.sh https://github.com/TUO-UTENTE/cyberdistro.git
#
#   # caricare il codice E far partire la build della ISO + Release v0.1.0:
#   ./scripts/publish-to-github.sh https://github.com/TUO-UTENTE/cyberdistro.git v0.1.0
#
# PREREQUISITI:
#   - git installato  (Windows: Git for Windows; macOS: xcode-select --install; Linux: apt install git)
#   - un repository creato su GitHub (Passo 3 della guida), anche vuoto
#   - autenticazione: la prima push chiederà di accedere a GitHub
#     (si apre il browser, oppure usa un Personal Access Token come password).
set -euo pipefail

say(){ printf '\033[1;36m›\033[0m %s\n' "$*"; }
err(){ printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ask(){ read -r -p "$1 [s/N] " a; [ "${a,,}" = "s" ] || [ "${a,,}" = "y" ]; }

REMOTE="${1:-}"
TAG="${2:-}"
[ -n "$REMOTE" ] || err "Manca l'URL del repository. Uso: $0 <URL-repo> [vX.Y.Z]"
command -v git >/dev/null || err "git non è installato."

# Deve girare dalla cartella del progetto (quella che contiene build/ e security-center/).
[ -d build ] && [ -d security-center ] || \
    err "Esegui lo script dalla cartella del progetto (dove ci sono build/ e security-center/)."

# 1) repo git locale
if [ ! -d .git ]; then
    say "Inizializzo il repository git locale…"
    git init -q
    git branch -M main
fi

# 2) remote
if git remote get-url origin >/dev/null 2>&1; then
    CUR="$(git remote get-url origin)"
    if [ "$CUR" != "$REMOTE" ]; then
        say "Aggiorno il remote 'origin' → $REMOTE"
        git remote set-url origin "$REMOTE"
    fi
else
    say "Collego il remote 'origin' → $REMOTE"
    git remote add origin "$REMOTE"
fi

# 3) commit
git add -A
if git diff --cached --quiet; then
    say "Nessuna modifica da committare (il codice è già aggiornato)."
else
    MSG="${COMMIT_MSG:-CyberDistro: pubblicazione sorgenti}"
    say "Creo il commit: \"$MSG\""
    git -c user.name="${GIT_NAME:-CyberDistro}" \
        -c user.email="${GIT_EMAIL:-you@example.com}" \
        commit -q -m "$MSG"
fi

# 4) push
say "Invio il codice su GitHub (branch main)…"
say "Se è la prima volta, verrà chiesto di autenticarti."
git push -u origin main

# 5) tag opzionale → fa partire la build della ISO + Release
if [ -n "$TAG" ]; then
    case "$TAG" in
        v[0-9]*) : ;;
        *) err "Il tag deve avere la forma vX.Y.Z (es. v0.1.0). Ricevuto: $TAG";;
    esac
    if git rev-parse "$TAG" >/dev/null 2>&1; then
        err "Il tag $TAG esiste già. Usa un numero nuovo (es. v0.1.1)."
    fi
    echo
    say "Il tag $TAG farà partire il workflow 'Build ISO' su GitHub,"
    say "che costruirà la ISO e pubblicherà la Release con checksum e SBOM."
    if ask "Creo e invio il tag $TAG ora?"; then
        git tag -a "$TAG" -m "CyberDistro $TAG"
        git push origin "$TAG"
        say "Tag inviato. Segui l'avanzamento nella scheda 'Actions' del repo."
    else
        say "Tag annullato. Potrai crearlo più tardi con: git tag $TAG && git push origin $TAG"
    fi
fi

echo
say "Fatto. Apri il tuo repository su GitHub per vedere i file"
[ -n "$TAG" ] && say "e la scheda 'Actions' per la build della ISO."
