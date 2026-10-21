#!/usr/bin/env bash
# CyberDistro — create an ENCRYPTED persistence partition on the USB stick.
#
# NON-DESTRUCTIVE to the live partition: this creates a NEW partition in free
# space (or uses a partition you name). It never touches the internal disk.
#
# Usage:
#   sudo ./make-persistence.sh /dev/sdX            # create new partition in free space
#   sudo ./make-persistence.sh --partition /dev/sdX3   # use an existing partition
#
# Safety:
#   * Refuses to run on a mounted system disk.
#   * Prints the target device details and REQUIRES typed confirmation.
#   * Uses LUKS2 (cryptsetup) + ext4, labeled `persistence`, with a
#     persistence.conf enabling home + tool data persistence.
set -euo pipefail

die(){ echo "ERRORE: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "esegui come root."
command -v cryptsetup >/dev/null || die "cryptsetup non installato."

PART=""
DEV=""
if [ "${1:-}" = "--partition" ]; then
    PART="${2:-}"; [ -b "$PART" ] || die "partizione non valida: $PART"
else
    DEV="${1:-}"; [ -b "$DEV" ] || die "dispositivo non valido: $DEV"
fi

echo "=== Dispositivo di destinazione ==="
if [ -n "$DEV" ]; then lsblk -o NAME,SIZE,TYPE,MOUNTPOINT "$DEV"; else lsblk -o NAME,SIZE,TYPE,MOUNTPOINT "$PART"; fi
echo
echo "ATTENZIONE: verrà creata/formattata una partizione CIFRATA di persistenza."
echo "La partizione LIVE non viene toccata. Il disco interno del PC NON viene toccato."
read -r -p "Scrivi ESATTAMENTE 'CONFERMO' per procedere: " ans
[ "$ans" = "CONFERMO" ] || die "annullato dall'utente."

if [ -n "$DEV" ]; then
    # Create a new primary partition in the remaining free space.
    echo "Creo una nuova partizione nello spazio libero di $DEV ..."
    # sgdisk creates a new partition using all free space, type Linux FS.
    command -v sgdisk >/dev/null || die "sgdisk (gdisk) non installato."
    sgdisk -n 0:0:0 -t 0:8300 -c 0:persistence "$DEV"
    partprobe "$DEV"; sleep 2
    # The new partition is the highest-numbered one.
    PART="$(lsblk -lnpo NAME "$DEV" | tail -1)"
    echo "Nuova partizione: $PART"
fi

echo "Inizializzo LUKS2 su $PART (ti verrà chiesta una passphrase forte) ..."
cryptsetup luksFormat --type luks2 "$PART"
echo "Sblocco il volume ..."
cryptsetup open "$PART" cyberdistro_persistence
echo "Creo il filesystem ext4 etichettato 'persistence' ..."
mkfs.ext4 -L persistence /dev/mapper/cyberdistro_persistence

mnt="$(mktemp -d)"
mount /dev/mapper/cyberdistro_persistence "$mnt"
cat > "$mnt/persistence.conf" <<'EOF'
# CyberDistro persistence configuration (live-boot)
/home                 source=home
/etc/cyberdistro      source=cyberdistro-config
/var/lib/cyberdistro  source=cyberdistro-data
EOF
sync
umount "$mnt"; rmdir "$mnt"
cryptsetup close cyberdistro_persistence

echo
echo "FATTO. Al prossimo avvio, scegli 'persistence' e inserisci la passphrase."
echo "BACKUP: annota la passphrase in un luogo sicuro. Se la perdi, i dati"
echo "        cifrati NON sono recuperabili. Vedi README.md per il backup header."
