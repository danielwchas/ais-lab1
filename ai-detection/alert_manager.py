#!/usr/bin/env python3
"""Larmhanterare som integrerar med anomalidetektorn."""

import json
import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('alerts.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

ALERT_THRESHOLDS = {
    'critical': {'zscore': 3.0, 'isolation_score': -0.3},
    'high':     {'zscore': 2.5, 'isolation_score': -0.2},
    'medium':   {'zscore': 2.0, 'isolation_score': -0.1},
}


def classify_alert(zscore: float, isolation_score: float) -> str | None:
    """Klassificera en anomali baserat på tröskelvärden."""
    for level, thresholds in ALERT_THRESHOLDS.items():
        if abs(zscore) >= thresholds['zscore'] or isolation_score <= thresholds['isolation_score']:
            return level
    return None


def create_alert(timestamp, severity, details: dict) -> dict:
    """Skapa ett strukturerat larmobjekt."""
    return {
        'timestamp': str(timestamp),
        'severity': severity,
        'detected_at': datetime.now().isoformat(),
        'details': details,
    }


def write_alerts_to_file(alerts: list, filepath: str = 'active_alerts.json'):
    """Skriv larm till JSON-fil (kan integreras med Wazuh)."""
    with open(filepath, 'w') as f:
        json.dump(alerts, f, indent=2, default=str)
    logger.info(f"Skrev {len(alerts)} larm till {filepath}")


def process_anomaly_results(csv_path: str = 'anomaly_results.csv'):
    """Läs anomaliresultat och generera larm."""
    import pandas as pd
    df = pd.read_csv(csv_path, index_col=0, parse_dates=True)

    alerts = []
    for idx, row in df.iterrows():
        severity = classify_alert(row['event_count_zscore'], row['anomaly_score'])
        if severity:
            alert = create_alert(idx, severity, {
                'event_count': int(row['event_count']),
                'avg_severity': round(row['avg_severity'], 2),
                'unique_ips': int(row['unique_ips']),
                'anomaly_score': round(row['anomaly_score'], 4),
                'zscore': round(row['event_count_zscore'], 2),
            })
            alerts.append(alert)
            logger.warning(f"[{severity.upper()}] Anomali vid {idx}: "
                           f"{int(row['event_count'])} händelser, z={row['event_count_zscore']:.2f}")

    write_alerts_to_file(alerts)
    return alerts


if __name__ == '__main__':
    alerts = process_anomaly_results()
    print(f"\nTotalt {len(alerts)} larm genererade")
    for a in alerts:
        print(f"  [{a['severity'].upper()}] {a['timestamp']} — "
              f"{a['details']['event_count']} händelser")
