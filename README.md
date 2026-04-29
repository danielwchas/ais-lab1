# Lab 1 - Centraliserad säkerhetsövervakning






### Wazuh installerat och med aktiv agent
![active-agent](/screens/agent_active.png)

### Minst 3 egna detektionsregler implementerade
[local_rules.xml](../local_rules.xml)

### File Integrity Monitor konfigurerat
[ossec.conf](../ossec.conf)
![file_integrity_monitor](/screens/file_integrity_monitor_config.png)

### Dashboard med säkerhetsöversikt
![dashboard](/screens/dashboard.png)

### Automatiserad incidentrespons
[response_playbook.py](../ai-detection/response_playbook.py)

### Pythonscript för anomalidetektering med dokumenterade resultat
[anomaly_detector.py](../ai-detection/anomaly_detector.py)
![ai_defender_script](../screens/anomaly_detector.png)
