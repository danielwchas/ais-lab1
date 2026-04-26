#!/usr/bin/env python3
"""
Automatiserad incidentrespons-playbook.
Hanterar: blockering, isolering, larmning och loggning.
"""

import json
import subprocess
import logging
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('incident_response.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IncidentResponder:
    def __init__(self):
        self.incidents = []
        self.blocked_ips = set()

    def block_ip(self, ip: str, reason: str, duration: int = 3600):
        """Blockera en IP-adress via iptables."""
        if ip in self.blocked_ips:
            logger.info(f"IP {ip} redan blockerad")
            return

        try:
            subprocess.run(
                ['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True
            )
            self.blocked_ips.add(ip)
            logger.warning(f"BLOCKERAD: {ip} — {reason} (varaktighet: {duration}s)")

            self.log_incident('block_ip', {
                'ip': ip, 'reason': reason, 'duration': duration
            })
        except subprocess.CalledProcessError as e:
            logger.error(f"Kunde inte blockera {ip}: {e}")

    def isolate_agent(self, agent_id: str, reason: str):
        """Isolera en agent genom att begränsa dess nätverksåtkomst."""
        logger.warning(f"ISOLERING: Agent {agent_id} — {reason}")
        self.log_incident('isolate_agent', {
            'agent_id': agent_id, 'reason': reason
        })

    def send_alert(self, severity: str, message: str):
        """Skicka larm (logga till fil, kan utökas med e-post/webhook)."""
        alert = {
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        logger.warning(f"LARM [{severity.upper()}]: {message}")

        # Skriv till larmfil
        alerts_file = Path('response_alerts.json')
        existing = json.loads(alerts_file.read_text()) if alerts_file.exists() else []
        existing.append(alert)
        alerts_file.write_text(json.dumps(existing, indent=2))

    def log_incident(self, action: str, details: dict):
        """Logga incident för dokumentation."""
        incident = {
            'action': action,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.incidents.append(incident)

        # Spara alla incidenter
        with open('incident_log.json', 'w') as f:
            json.dump(self.incidents, f, indent=2, default=str)

    def process_alert(self, alert: dict):
        """Hantera ett inkommande larm enligt playbook."""
        severity = alert.get('severity', 'medium')
        details = alert.get('details', {})
        src_ip = details.get('src_ip', '')

        logger.info(f"Behandlar larm: {severity} — {json.dumps(details)}")

        if severity == 'critical':
            # Kritiskt: blockera, isolera, larma
            if src_ip:
                self.block_ip(src_ip, 'Kritisk anomali detekterad')
            self.send_alert('critical', f'Kritisk incident: {details}')

        elif severity == 'high':
            # Högt: blockera och larma
            if src_ip:
                self.block_ip(src_ip, 'Hög anomali detekterad', duration=1800)
            self.send_alert('high', f'Hög incident: {details}')

        elif severity == 'medium':
            # Medium: enbart larm och loggning
            self.send_alert('medium', f'Medium incident: {details}')


if __name__ == '__main__':
    responder = IncidentResponder()

    # Läs AI-genererade larm
    try:
        with open('active_alerts.json') as f:
            alerts = json.load(f)
    except FileNotFoundError:
        print("Kör anomaly_detector.py och alert_manager.py först")
        exit(1)

    print(f"Behandlar {len(alerts)} larm...")
    for alert in alerts:
        responder.process_alert(alert)

    print(f"\nFärdigt. {len(responder.incidents)} åtgärder vidtagna.")
    print(f"Blockerade IP:n: {responder.blocked_ips}")
    print("Se incident_log.json och incident_response.log för detaljer.")