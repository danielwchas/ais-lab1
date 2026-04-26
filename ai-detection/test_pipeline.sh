#!/usr/bin/env bash
# Steg 1: Generera testattacker
echo "=== Startar testattack ==="
hydra -l root -P /tmp/passwords.txt ssh://localhost -t 4 &
nmap -F localhost &
sudo touch /etc/test-incident-file

# Steg 2: Vänta på att Wazuh bearbetar händelserna (30-60 sek)
sleep 60

# Steg 3: Exportera nya larm
echo "=== Exporterar larmdata ==="
curl -k -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_search?size=10000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' \
  | python3 -m json.tool > test_alerts.json

# Steg 4: Kör AI-detektion
echo "=== Kör anomalidetektering ==="
python3 anomaly_detector.py test_alerts.json

# Steg 5: Generera larm
echo "=== Genererar larm ==="
python3 alert_manager.py

# Steg 6: Kör responsplaybook
echo "=== Kör incidentrespons ==="
python3 response_playbook.py

echo "=== Pipeline komplett ===" 