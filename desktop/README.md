# Desktop — esperienza macOS-inspired (senza asset Apple)

Obiettivo: eleganza, coerenza e semplicità ispirate a macOS, ottenute
**configurando KDE Plasma**, non riscrivendo un DE. Nessun logo, icona, font o
asset proprietario Apple.

## Scelte
- **KDE Plasma** (Wayland, fallback X11): altamente tematizzabile, mantenuto,
  HiDPI/scaling e accessibilità solidi, due temi (chiaro/scuro) nativi.
- **Pannello superiore**: stato di sistema (rete, privacy, batteria, notifiche) +
  global menu. **Dock inferiore**: app preferite e finestre aperte.
- **Launcher centrale / ricerca universale**: KRunner (app, file, guide, azioni).
- **Icone/font liberi**: Papirus (icone), Inter/Noto (font). Nessun font senza
  licenza.
- **Animazioni** leggere (compositor), disattivabili sul profilo *Basic*.

## Dove vivono le configurazioni
Le configurazioni di Plasma, SDDM e tema sono applicate nell'immagine tramite:
- pacchetti: `build/config/package-lists/00-system.list.chroot`
- file di skel/sistema: `build/config/includes.chroot/` (es. `/etc/skel` per i
  default del profilo utente `analyst`)
- **look-and-feel `org.cyberdistro.desktop`** (`desktop/look-and-feel/`): layout
  dei pannelli (`contents/layouts/org.kde.plasma.desktop-layout.js`) e default di
  tema/icone (`contents/defaults`). È selezionato per tutti gli utenti da
  `/etc/xdg/kdeglobals` (`LookAndFeelPackage=`), così plasmashell lo applica al
  primo avvio. Barra inferiore: menu → Impostazioni di sistema → **Security
  Center** → File → Terminale → Tor Browser. L'hook `0250-desktop-layout`
  verifica che ogni launcher esista.

## Accessibilità
- Lettore schermo **Orca**, scaling, contrasto elevato (temi Plasma), scorciatoie.
- Obiettivo: le operazioni comuni completabili senza terminale.

## Localizzazione
- Interfaccia **it/en** complete (vedi `security-center/.../i18n/`); architettura
  pronta per altre lingue (file YAML per lingua).

## Stato
Configurato (package-list, includes, look-and-feel). **Non avviato** in questo
ambiente (nessun display): la resa del layout va verificata su VM/hardware.
