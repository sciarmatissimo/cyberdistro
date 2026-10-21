# NOTICE — licenze e avvertenze legali

## Licenza del progetto
Il codice **originale** di CyberDistro (Security Center, script di build,
configurazioni, documentazione) è rilasciato sotto **GPL-3.0-or-later**
(vedi `LICENSE`).

## Software di terze parti
La distribuzione aggrega software di terze parti, ciascuno con la **propria
licenza**. L'elenco completo con le licenze è in:
- `sbom/cyberdistro.cdx.json` (CycloneDX, generato da `sbom/generate-sbom.py`)
- `licenses/components.md` (sintesi leggibile)

### Principi di inclusione rispettati
- Inclusi solo componenti la cui licenza **consente la redistribuzione** del
  binario nella ISO.
- Componenti con vincoli che **non** consentono la redistribuzione sono offerti
  come **installazione opzionale guidata** (scaricati dalla fonte ufficiale al
  primo uso), non inclusi nella ISO. Esempio: **Burp Suite Community** non è
  incluso; il Security Center ne propone l'installazione dalla fonte ufficiale.
- **Tor Browser** è incluso come build **ufficiale** del Tor Project, verificata
  via GPG, **non ri-pacchettizzata**, per non comprometterne la fingerprint
  resistance (MPL-2.0 / marchi del Tor Project).
- Nessuna credenziale, chiave privata o token è incorporata.
- Nessun software pirata o da fonti non verificate.
- Nessun marchio/logo di terzi è usato in modo da suggerire un'affiliazione
  inesistente. "Kali", "Debian", "Tor", "Apple", "macOS" sono marchi dei
  rispettivi titolari; qui citati solo a fini descrittivi/di riferimento.

## Avvertenza d'uso
Strumento destinato ad attività **autorizzate** (apprendimento, ricerca, test su
sistemi propri o con autorizzazione scritta). L'ambito dichiarato nel Security
Center registra l'intenzione dell'operatore e **non** costituisce né sostituisce
un'autorizzazione legale. L'uso non autorizzato è illegale. La responsabilità è
interamente dell'operatore.
