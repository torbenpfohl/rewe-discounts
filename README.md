# Einleitung

Nach Änderungen von Rewe (siehe [#19](https://github.com/foo-git/rewe-discounts/issues/19)) braucht es nun einen privaten Schlüssel und ein Zertifikat. Beide sind in der Rewe APK zu finden. get_creds.py ist der Versuch das Extrahieren zu automatisieren. Bitte mit Bedacht nutzen.

# Rewe Discounts

Dieses Programm sucht mittels der Rewe-API für einen bestimmten Rewe-Markt die aktuellen
Angebote und schreibt eine Markdown-formatierte Übersichtsliste heraus.

Zur besseren Preisvergleichbarkeit wird der Preis pro Referenzmenge
(z.B. 100 g oder 100 ml) mit ausgegeben. 

Anwendungsbeispiel:
* Sonntags lädt der Server (z.B. Raspberry Pi/Debian) per cron-Job die
neuen Angebote herunter, und speichert sie als Notiz in einer Nextcloud-Instanz
zum komfortablen Abruf per Smartphone.

## Abhängigkeiten (Dependencies)
- `$ pip install httpx[http2]`  Um die Rewe APK herunterzuladen und den privaten Schlüssel und das Zertifikat zu extrahieren. 
- `$ pip install requests`   Error.
- `$ pip install cryptography`   Verarbeiten der pfx-Datei.

## Verwendung (Usage)

* Aktuelles Release [herunterladen](https://github.com/foo-git/rewe-discounts/releases) bzw. Master-Branch klonen.
* `python3 ./rewe_discounts/rewe_discounts.py` ausführen und Hilfetext durchlesen.
    * Mit `rewe_discounts.py --list-markets PLZ` lässt sich für eine beliebige Postleitzahl (PLZ) eine Marktliste inklusive der Market ID ausgeben lassen.
    * Wähle einen Markt und kopiere die ID, z.B. "562286".
    * Durch `rewe_discounts.py --market-id 562286 --output-file "Angebote Rewe.md"` werden die Angebote des Markets in eine Datei geschrieben. 

Ein Ausschnitt von `Angebote Rewe.md` sieht beispielsweise so aus:
```
# Kochen & Backen
Gültig diese Woche bis Samstag, 30.05.2020

**Barilla Pasta**
- 0.79, 1 kg = 1.58
- versch. Ausformungen, je 500-g-Pckg.

**Knorr Grillsauce**
- 0.65, 100 ml = 0.26
- versch. Sorten, je 250-ml-Fl.

**Erasco Eintopf**
- 1.49, 1 kg = 1.86
- versch. Sorten, je 800-g-Dose

**Mondamin Milchreis im Becher**
- 0.79, 100 g = 1.36
- je 58-g-Becher
```

Es lassen sich bestimmte Produkte auch hervorheben und an erster Stelle der Datei platzieren.
Hierzu wird noch eine Textdatei angelegt, und pro Zeile ein Suchbegriff wie "Nudeln" oder "Joghurt" eingegeben:

`rewe_discounts.py --market-id 562286 --output-file "Angebote Rewe.md" --highlights=highlights.txt`

Ganz großes SORRY vorab, ich kenne mich mit Github nur ganz wenig aus und hoffe, hier kein zu großes Durcheinander zu erzeugen. Leider finde ich keinen anderen Weg, einen Kommentar loszuwerden. 
Erst mal vielen Dank für das Script. Seit sich bei Rewe ohne Javascript die Seite nicht mehr duchsuchen läßt, kam das wie gerufen und funktioniert bestens. Bei Aldi/Lidl durchkämme ich seit längerem und noch erfolgreich die normale Webseite. Bei Penny.de und Netto-online.de oder auch Norma geht das leider gar nicht. Hast Du Dir das schon mal angesehen - gibt es eine ähnlich elegante Möglichkeit?
