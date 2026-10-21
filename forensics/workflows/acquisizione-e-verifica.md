# Workflow forense — acquisizione e verifica dell'integrità

Workflow guidato (Beginner → Expert). Principi: ripetibilità, tracciabilità,
conservazione delle evidenze, copie di lavoro separate dagli originali.

## Prerequisiti
- Progetto creato nel Security Center (owner + caso).
- Dove possibile, **write-blocker hardware** sull'originale. Il sistema **non**
  può garantire la protezione da scrittura via software: se usi solo software,
  dichiaralo come tale (non come garanzia).

## Passi
1. **Documenta lo stato iniziale**: dispositivo, numeri di serie, data/ora,
   operatore. Il Security Center registra tutto nel log del progetto.
2. **Hash dell'originale (se accessibile in sola lettura)**: calcola SHA-256
   (wrapper `forensic-hash`). Questo è il valore di riferimento.
3. **Acquisizione**: crea un'immagine forense con strumenti dedicati
   (`ewfacquire`/`dc3dd`/`dcfldd`). Lavora verso un supporto di destinazione
   pulito. Non modificare l'originale.
4. **Hash dell'immagine**: calcola SHA-256 dell'immagine acquisita e
   **confrontalo** con quello dell'originale (verifica di corrispondenza).
5. **Lavora sulle copie**: tutte le analisi successive (Sleuth Kit, Autopsy,
   Volatility per la RAM) avvengono su **copie**, mai sull'originale.
6. **Timeline ed evidenze**: ricostruisci la timeline (Plaso/log2timeline);
   marca i risultati con confidenza (confermato/probabile/possibile/falso
   positivo) e separa le interpretazioni dai dati.
7. **Verifica periodica**: ri-calcola gli hash per dimostrare che le evidenze
   non sono cambiate (catena di custodia).
8. **Report**: data/ora, versioni degli strumenti, parametri, hash, operatore.
   Export JSON/HTML/PDF dal Security Center.

## Limiti dichiarati
- Nessuna garanzia di write-protection software.
- Nessuna garanzia di cancellazione forense di RAM o flash (wear-leveling).
- La memoria volatile (RAM) va acquisita prima dello spegnimento se rilevante;
  dopo lo spegnimento i dati in RAM non sono garantiti.
