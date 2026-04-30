Credentials used in this project are default lab settings and are not used in production.

# Lab 1 - Centraliserad säkerhetsövervakning
En labb för att sätta upp och använda Wazuh som centraliserad säkerhet.  
Labben föreslår/kräver Ubuntu, men eftersom jag inte gillar Ubuntu och använder mig av CachyOS med fish shell (istället för bash) hemma så har jag fått skriva om många kommandon. fish shell beter sig lite annorlunda mot bash, men det har fungerat när jag har tagit mig förbi det.  
Jag har satt upp Wazuh på en stationär dator hemma, där jag har gjort det mesta av jobbet. Jag satte även upp Wazuh på en laptop, men jag har inte gjort något av labben på den.  
I /Dokumentation finns tidslinje, en fil på de kommandon jag har använt, och dokumentationen som ligger till grund för den här README.md-filen.  

### Reflektion (max 1 sida)
Labben har visat på stora fördelar med en centraliserad säkerhetslösning. Redan nu, dagen innan labben ska vara inlämnad, har jag upptäckt ett tydligt samband med yrkesrollen: 
Några av oss var på ett webinar om Mythos, där en av föreläsarna gick igenom en händelse där någon hackade ett lands skattemyndighet. Myndigheten hade kunnat upptäcka intrånget mycket tidigare än de gjorde, då signalerna var  
**Hög nätverksvolym**  
**Filändringar i produktion**  
**Identitets- och dataavikelser**  
Alla tre är saker som Wazuh, även utan en AI-modul, kan upptäcka. Det visar på vikten av ett fungerande och rätt konfigurerat system för att upptäcka och hantera säkerhetshändelser.  
Angriparen hade använt sig av två AI-system för att ta sig in. Om säkerheten hade varit bättre skulle det fortfarande upptäckts. Men det kommer bli vanligare att mer kompetenta angripare använder sig av AI i framtiden, och då måste de som ska skydda system hänga med. Det är lättare om systemen då har ett AI-försvar. Vi har lärt oss att det inte är så svårt att ställa in, även om det kanske inte är helt perfekt konfigurerat hos oss än.  

Vi har lärt oss hur att skriva egna regler. Såna regler kan vara så enkla eller så komplexa man vill ha dem. Standardreglerna täcker det mesta, men det finns fortfarande många miljöspecifika hot där det inte finns någon detektion.

En annan sak som har varit intressant är att jag har fått lära mig mer om skillnaderna på hur olika Linux-shell skriver kommandon. Oftaste har det varit små saker, som hur fish hanterar variabler jämfört med bash. Båda går att använda, men på olika sätt.

## Uppgifter i labben
### Del 1 - Dokumentera minst 5 standardregler du hittar och beskriv vad de detekterar
Reglerna finns ävedn uppskrivna i [lab1-arbetsdokument.docx](/Dokumentation/lab1_arbetsdokument.docx).

| Regel-ID | Beskrivning | Nivå | Logik & Funktion |
| :--- | :--- | :---: | :--- |
| **521** | Possible kernel level rootkit | **11** | Triggas efter en `rootcheck`. Indikerar allvarlig systemkompromettering som kräver att klienten genast kopplas från nätverket. |
| **5715** | SSHD: Accepted password/publickey | **3** | Underregel till 5700. Loggar lyckad SSH-autentisering. Nivå 3 används för att bevaka legitima inloggningar som kan vara kontomissbruk. |
| **5716** | SSHD: Authentication failed | **5** | Underregel till 5700. Triggas vid misslyckade inloggningsförsök. Har en högre nivå än 5715 då det kan indikera brute force-försök. |
| **40113** | Multiple viruses - Possible outbreak | **12** | **Frekvensregel:** Triggas om regel 52502 aktiveras 8 gånger inom 360 sekunder. Indikerar ett kritiskt virusutbrott/malware-attack. |
| **52500** | Clamd messages grouped | **0** | **Sorteringsregel:** Sorterar loggar från ClamAV (`clamd`). Nivå 0 innebär att den inte larmar, utan skickar loggen vidare till rätt underregel. |
| **52502** | ClamAV: Virus detected | **8** | Underregel till 52500 via `if_sid`. Letar specifikt efter ordet "virus" i loggar som identifierats komma från ClamAV-tjänsten. |
| **92060** | Suspicious process (RTLO) | **15** | **Sysmon:** Detekterar "Right-to-Left Override"-tecken som används för att dölja filändelser (t.ex. att en `.exe` ser ut som en `.txt`). |
| **99614** | MS Graph: Malicious activities | **15** | **Cloud:** Rapport från Microsoft Graph om bekräftad skadlig aktivitet. Kräver omedelbar inaktivering av användarkontot och dess sessioner. |

### Del 2 - Dokumentera resultaten: vilka larm utlöstes, hur lång tid tog det, och vilka attacker missades?
[detection_comparison.json](detection_comparison.json)  
Brute force-attacker upptäcks nästan direkt, inom en sekund. Vid mina tester kunde det ta upp till 24 sekunder för en filändring att detekteras av standardreglerna. Jag vet inte om det beror på mitt testförfarande.  
Portskanning med nmap upptäcks inte med standardreglerna.  

### Del 3 - Dokumentera och beskriv vilka hot som AI-detektorn hittar bättre respektive sämre än traditionella regler
Mer utförligt i VG-delen längre ner.  
AI-detektorn hittar saker som slow brute force, och är snabbare på filändringar. Både AI och regler är lika dåliga på att upptäcka portskanningar, men det går förbättra.  
I och med att AI-skriptet måste köras för att AI-detektorn ska hitta någonting så kan det försenas när skriptet inte är aktivt. Då kan standardregler vara snabbare.

### Del 4
Följer nedan.

## G-Krav Checklista

### Wazuh installerat och med aktiv agent
![active-agent](/screens/agent_active.png)

### Minst 3 egna detektionsregler implementerade
[local_rules.xml](/local_rules.xml)

### File Integrity Monitor konfigurerat
[ossec.conf](/ossec.conf)  
![file_integrity_monitor](/screens/file_integrity_monitor_config.png)

### Dashboard med säkerhetsöversikt
![dashboard](/screens/dashboard.png)

### Automatiserad incidentrespons
[response_playbook.py](/ai-detection/response_playbook.py)

### Pythonscript för anomalidetektering med dokumenterade resultat
[anomaly_detector.py](/ai-detection/anomaly_detector.py)  
![ai_defender_script](/screens/anomaly_detector.png)

### Systemöversikt
Wazuh är en centraliserad säkerhetsplattform. Den utgår från en server, och det finns agenter installerade på klient-maskiner som registrerar händelser.  
Agenterna samlar in loggar och övervakar filer. Datan skickas sedan till servern som analyserar i realtid mot fördefinierade regelverk. Datan lagras med Wazuh Indexer och kan sedan visualiseras för användaren med Wazuh Dashboard.  
I vår miljö har vi även implementerat ett AI-skript för att upptäcka vissa saker som traditionella regler inte kan se.

### Nätverksdiagram
![networkdiagram](/screens/wazuhflow.png)  

### Komponenter
| Komponent | Version | Roll | Port |  
|-----------|---------|------|------|  
| Wazuh Manager | 4.14.4 | SIEM-motor, regelmotor | 1514, 1515, 55000 |  
| Wazuh Indexer | 4.14.4 | Logglagring (OpenSearch) | 9200 |  
| Wazuh Dashboard | 4.14.4 | Webbgränssnitt | 443 |  
| Wazuh Agent | 4.14.4 | Loggsamlare | - |  
| [AI-modul](/ai-detection/anomaly_detector.py) | - | Anomalidetektering | - |  
| [Slow Brute Force](/ai-detection/slow_attack.sh) | - | Slow Brute Force-attack | - |
| [AI Defender](/ai-detection/ai_defender.sh) | - | Alla testattacker och AI-skydd i ett skript | - |
| [Pipeline Test](/ai-detection/test_pipeline.sh) | - | Testar hela Pipelinen | - |
| [Alert Manager](/ai-detection/alert_manager.py) | - | Larmhanterare som integrerar med anomalidetektorn | - |

### Detektionsregler
Triggade standardregler
| Regel-ID | Beskrivning | MITRE ID | Taktik / Teknik |
| :--- | :--- | :--- | :--- |
| **550** | FIM: Integrity checksum changed (File modified) | **T1565.001** | Data Manipulation |
| **554** | FIM: File added to system | **T1222** | File and Directory Permissions Modification |
| **651** | Host blocked by firewall/active response | **T1562.001** | Impair Defenses: Disable or Modify Tools |
| **2501** | User-defined active response triggered | **T1562** | Impair Defenses |
| **5402** | Successful sudo to ROOT user | **T1548.001** | Abuse Elevation Control Mechanism: Sudo/Su |
| **5501** | PAM: Login session opened | **T1078** | Valid Accounts |
| **5502** | PAM: Login session closed | - | (Informationslogg) |
| **5503** | PAM: Authentication success | **T1078** | Valid Accounts |
| **5557** | Roundcube Webmail login success | **T1078** | Valid Accounts |
| **5760** | SSHD: Authentication success | **T1021.004** | Remote Services: SSH |

Lokala regler
| Regel-ID | Beskrivning | MITRE ID | Kommentar |
| :--- | :--- | :--- | :--- |
| **100001** | SSH Brute force-attack (5+ misslyckade försök) | **T1110** | Triggad av Hydra-attack |
| **100002** | Lyckad inloggning efter brute force-detektering | **T1110** | Indikerar komprometterat konto |
| **100003** | SSH-inloggning från extern/oväntad IP | **T1078** | Vitlistning av kända nätverk |
| **100010** | AI-anomalidetektering: Kritisk avvikelse | - | Baserad på JSON-payload (Severity: Critical) |
| **100011** | AI-anomalidetektering: Hög avvikelse | - | Baserad på JSON-payload (Severity: High) |

### Incidentrespons
Jag utförde en Hydra-attack från en annan dator mot min klient. Hydra gjorde ett antal inloggningsförsök. Wazuh-agenten detekterade detta och skickade loggarna till Wazuh Manager. Managern matchade i sin tur loggarna mot min lokala regel 100001.  
Regel 100001 har en hög prioriteringsnivå vilket triggade en förkonfigurerad Active Response-modul. Managern skickade ett kommando till Agenten för att trigga regel 651 och blockera angriparens IP.  
Attacken stoppades och angriparen kunde inte göra fler försök. Det hindrar inte riktiga användare från att komma åt systemet.  

## VG-Krav Checklista
### Fullständigt automatiserad säkerhetsövervakningslösning som detekterar hot
Wazuh-agenten ligger och kör konstant i minnet. För att göra hela flödet automatiskt kan man köra ![AI Defender](ai-detection/ai_defender.sh)-skriptet i bakgrunden antingen i en terminal eller som en systemtjänst. Antagligen bör man justera detektionstider för ens enskilda behov.  
Ett annat alternativ är att köra skriptet som cron-jobb.

### Egna AI-algoritmer för hotjakt som förbättrar detektionstiden med minst 40% jämfört med traditionella metoder
AI upptäcker (enligt mina tester) filändringar 20 sekunder snabbare än regel-baserad detektion.  
AI upptäcker slow brute force över huvud taget, det är tveksamt om det finns standardregler för det.  
Man kan tänka sig att AI tränas på när användare loggar in. Lägger man till en regel för att detektera lyckade inloggningar och även har raden `<time>18:00-06:00</time>` i regeln så kommer det ses som en anomali. I annat fall kan hotaktörer logga in eller försöka logga in utanför kontorstid, och då upptäcks inte det förrän någon läser av Wazuh Dashboard morgonen efter. Med AI kan det ses som en anomali och stoppas direkt.  
Det tycks inte finnas några regler för portskanningar. Där kan man lägga till egna regler, exempelvis  
```
<!-- Steg 1: Identifiera en misslyckad anslutning (t.ex. mot SSH eller brandvägg) -->
<rule id="100020" level="0">
    <if_sid>5700</if_sid> <!-- SSHD-grupp -->
    <match>Connection refused|Connection closed</match>
    <description>Möjlig misslyckad anslutning</description>
  </rule>

  <!-- Steg 2: Trigga larm om det sker många gånger från samma IP -->
  <rule id="100021" level="10" frequency="30" timeframe="60">
    <if_matched_sid>100020</if_matched_sid>
    <same_source_ip />
    <description>Portskanning detekterad: Många misslyckade anslutningar från samma IP</description>
    <mitre>
      <id>T1046</id> <!-- Network Service Scanning -->
    </mitre>
  </rule>
```
Utöver såna regler kan man lära AI att se mönster, som till exempel att någon IP pratar med 20 portar i stort sett samtidigt. Det går även lära AI att upptäcka när någon pratar med 5 portar, väntar 60 sekunder, och sedan pratar med 5 portar till.

### Dokumenterad jämförelse mellan regelbaserad och AI-stödd detektion med mätbara resultat
[detection_comparison.json](detection_comparison.json)  
Resultaten från prestandatestet i `detection_comparison.json` sammanställda:

| Testfall (Scenario) | Traditionell regel (sek) | AI-detektering (sek) | Förbättring (%) | Detekterad (Regel/AI) |
| :--- | :---: | :---: | :---: | :---: |
| **SSH Brute Force (10 försök)** | 3s | 3s | 0% | Ja / Ja |
| **Portskanning (Top 1000)** | -- | 5s | **Snabbare** | Nej / Ja |
| **Kritisk filändring** | 24s | 4s | **83.3%** | Ja / Ja |
| **Långsam Brute Force (1/min)** | -- | 2s | **Snabbare** | Nej / Ja |

Mina mätningar är bristfälliga. Det verkar inte finnas några regler som upptäcker portskanning. Jag fick ett resultat när jag testade med ett felaktigt skrivet AI-skript. Det som tycks skilja i tid är för filändringar.  
**Men**: AI-skriptet upptäcker inte någonting om det inte körs. Att låta det köra i en loop om och om igen är opraktiskt och slösar resurser. Därför är det bättre att köra det med ett visst intervall. Jag har kört det med 5 minuters intervall. Ett riktigt företag kanske kör varje timme.  
Men det blir nästan aldrig realtid med just vårt skript. Det går tillbaka och tittar i loggarna över tid. Därför kan standardreglerna ofta upptäcka hot innan AIn gör det, så länge det finns en regel för det. Ett säkert system förlitar sig inte bara på ett sätt att se hoten, och man får inte bli bekväm med att man har AI som lär sig upptäcka saker. Det kan fortfarande hända nånting på de 5 minuter där skriptet inte körs.  
Det ska finnas AI-lösningar som körs i realtid, men i vår labb har vi inte ett sådant.