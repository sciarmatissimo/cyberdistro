# Matrice di compatibilità

Regola di trasparenza: distinguere sempre **verificato** · **teoricamente
supportato, non testato** · **solo VM** · **non supportato** · **richiede
configurazione**. In alpha, **niente è ancora stato verificato su hardware
fisico**; la tabella elenca le aspettative di progetto, non promesse.

## Architettura
| Target | Stato | Note |
|---|---|---|
| x86-64 (Intel/AMD) | teoricamente supportato, non testato | Target primario |
| Mac Intel (x86-64) | teorico | Boot via ⌥; modelli T2 richiedono configurazione Startup Security |
| Apple Silicon (ARM64) | non supportato (boot USB nativo) | Solo VM / installazione assistita stile Asahi; immagine separata, fuori scope alpha |

## Firmware / boot
| Caratteristica | Stato atteso | Note |
|---|---|---|
| UEFI | supportato (da testare) | GRUB EFI |
| BIOS legacy | supportato (da testare) | isohybrid, GRUB PC |
| Secure Boot | **non supportato in alpha** | Non firmato; disattivare, oppure roadmap shim+MOK |
| USB 3.x | consigliato | Prestazioni adeguate |
| USB 2.0 | supportato, lento | Documentato |

## Requisiti hardware
| Profilo | CPU | RAM | Note |
|---|---|---|---|
| Basic | x86-64 dual-core | 4 GB | Strumenti essenziali, desktop leggero |
| Standard | x86-64 quad-core | 8 GB | Esperienza completa |
| Professional | x86-64 moderno | 16 GB+ | Forensics/RE, VM, memoria elevata |

## Periferiche
| Componente | Stato | Note |
|---|---|---|
| Wi-Fi integrato | dipende dal chip | Firmware inclusi (iwlwifi/realtek/atheros); **monitor mode** rilevata a runtime, non garantita |
| Adattatore Wi-Fi esterno | consigliato per wireless | Necessario se il chip integrato non supporta monitor mode |
| Ethernet | generalmente supportato | |
| GPU | modeset base | Accelerazione piena non garantita su tutte le GPU |
| Schermi HiDPI | supportato (Plasma scaling) | Da testare per modello |
| Sospensione/ripresa | da testare | Comportamento non garantito su tutti i firmware |

La matrice va aggiornata con risultati **reali** man mano che si testano modelli
specifici (produttore, modello, firmware, esito boot UEFI/BIOS, Wi-Fi, note).
