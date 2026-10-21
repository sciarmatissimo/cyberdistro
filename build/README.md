# Build — CyberDistro ISO

Questo albero è una configurazione **`live-build`** (Debian Live) completa. Non
contiene una ISO: la ISO si **genera** su un host Debian.

## Requisiti dell'host di build

- **SO:** Debian 12/13 amd64 (o container Debian `--privileged`).
- **Pacchetti:** `live-build debootstrap xorriso squashfs-tools mtools dosfstools grub-pc-bin grub-efi-amd64-bin python3-pip wget gnupg`
- **Privilegi:** root (live-build usa chroot e mount).
- **Rete:** accesso a `deb.debian.org`, `http.kali.org`, `dist.torproject.org`.
- **Risorse:** ~25 GB di disco liberi, ~2 GB RAM, e tempo (prima build: decine di minuti).

> ⚠️ **Perché non si builda nell'ambiente di sviluppo CI/sandbox:** la sandbox di
> sviluppo non ha accesso ai mirror Debian/Kali né ai privilegi di chroot/mount.
> La configurazione è reale e riproducibile; va eseguita su un host adeguato.

## Comando

```bash
sudo apt-get update
sudo apt-get install -y live-build debootstrap xorriso squashfs-tools \
    mtools dosfstools grub-pc-bin grub-efi-amd64-bin python3-pip wget gnupg
cd build
sudo ./build.sh            # oppure: sudo ./build.sh --clean
```

Output: `../iso/CyberDistro-PC-x86_64.iso` + `.sha256`.

## Creare la chiavetta USB avviabile

L'immagine è **isohybrid** (avvia da USB in UEFI e BIOS).

**Linux/macOS (`dd`)** — ⚠️ `of=` cancella l'intero dispositivo: verifica il nome!
```bash
lsblk                                  # individua la chiavetta, es. /dev/sdX
sudo dd if=iso/CyberDistro-PC-x86_64.iso of=/dev/sdX bs=4M status=progress oflag=sync
sync
```
**Multipiattaforma (consigliato ai principianti):** usa **balenaEtcher** o
**Rufus** (Windows), modalità "DD image".

## Persistenza cifrata

Dopo aver scritto la ISO, aggiungi una partizione di persistenza LUKS2 con lo
script dedicato (non distruttivo per la partizione live):
```bash
sudo ../security-center/../privacy/../scripts  # vedi privacy/persistence/README
sudo ./make-persistence.sh /dev/sdX            # vedi privacy/persistence/
```
(istruzioni dettagliate: `privacy/persistence/README.md`)

## Verifica dell'integrità

```bash
cd iso
sha256sum -c CyberDistro-PC-x86_64.iso.sha256
```
Confronta l'hash anche con quello pubblicato in `release/` (quando firmato).

## Troubleshooting

| Sintomo | Causa probabile | Rimedio |
|---|---|---|
| `lb: command not found` | live-build non installato | `apt-get install live-build` |
| Download fallisce a metà | mirror/rete | riprova; imposta un mirror vicino in `auto/config` |
| ISO non boota in UEFI | Secure Boot attivo | disattiva Secure Boot (alpha non firmata) |
| Boot lento da USB 2.0 | banda USB | usa USB 3.x; attiva `toram` |
| Chiave Kali non valida | keyring assente | il hook 0100 reinstalla/verifica la chiave |
