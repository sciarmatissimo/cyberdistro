# Persistenza cifrata (LUKS2)

## Cosa fa
Crea una partizione **cifrata** sulla chiavetta per conservare `/home`, le
configurazioni e i dati degli strumenti tra un avvio e l'altro. È **opzionale**:
senza di essa, ogni sessione è temporanea (modalità live).

- **Non distruttiva**: crea una nuova partizione nello spazio libero della
  chiavetta; la partizione live non viene modificata.
- **Mai sul disco interno**: gli script operano solo sul dispositivo USB indicato.
- **Cifratura**: LUKS2 con passphrase. Senza passphrase i dati non sono leggibili.

## Creare la persistenza
```bash
sudo ./make-persistence.sh /dev/sdX          # nuova partizione nello spazio libero
# oppure usare una partizione già esistente:
sudo ./make-persistence.sh --partition /dev/sdX3
```
Lo script mostra il dispositivo e richiede di digitare `CONFERMO`.

## Sbloccare / verificare
Al boot, scegli la voce **persistence** e inserisci la passphrase. Per verificare
manualmente da terminale:
```bash
sudo cryptsetup open /dev/sdX3 cyberdistro_persistence
sudo mount /dev/mapper/cyberdistro_persistence /mnt
ls /mnt
```

## Backup della passphrase e dell'header LUKS
- **Passphrase**: annotala in un gestore di password o su carta in luogo sicuro.
  Se la perdi, i dati **non** sono recuperabili (è lo scopo della cifratura).
- **Header LUKS** (consigliato): un header danneggiato rende i dati illeggibili
  anche con la passphrase giusta. Fai un backup dell'header:
  ```bash
  sudo cryptsetup luksHeaderBackup /dev/sdX3 --header-backup-file luks-header.img
  ```
  Conserva `luks-header.img` offline e in sicurezza. Ripristino:
  ```bash
  sudo cryptsetup luksHeaderRestore /dev/sdX3 --header-backup-file luks-header.img
  ```

## Limiti dichiarati
- La persistenza protegge i dati **a riposo** sulla chiavetta. Non protegge
  mentre il volume è sbloccato e montato.
- La cancellazione sicura/forense dei dati da flash **non è garantibile** a causa
  del wear-leveling dei controller NAND. Non promettiamo wipe forense.
- La RAM, i firmware e i dispositivi esterni possono conservare tracce fuori dal
  nostro controllo.
