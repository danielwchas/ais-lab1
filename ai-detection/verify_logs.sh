#!/usr/bin/env bash
# Kontrollera loggar
echo "--- Incidentlogg ---"
cat incident_log.json | python3 -m json.tool

echo "--- Blockerade IP:n ---"
sudo iptables -L INPUT -n | head -10

echo "--- Wazuh-larm ---"
docker exec -it single-node-wazuh.manager-1 \
  tail -5 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool

# Städa upp efter test
sudo rm -f /etc/test-incident-file