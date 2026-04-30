# Lab 1 - Centraliserad säkerhetsövervakning






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
| Regel-ID | Beskrivning | MITRE ID | Taktik / Teknik |
| :--- | :--- | :--- | :--- |
| **554** | File integrity monitoring (FIM): File added to system | **T1222** | File and Directory Permissions Modification |
| **5402** | Successful sudo to ROOT user | **T1548.001** | Abuse Elevation Control Mechanism: Sudo/Su |
| **5501** | PAM: Login session opened | **T1078** | Valid Accounts |
| **5502** | PAM: Login session closed | - | (Informationslogg) |
| **5503** | PAM: Authentication success | **T1078** | Valid Accounts |
| **5557** | Roundcube Webmail login success | **T1078** | Valid Accounts |
| **5760** | SSHD: Authentication success | **T1021.004** | Remote Services: SSH |