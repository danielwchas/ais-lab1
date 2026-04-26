#!/usr/bin/env python3
"""
AI-stödd anomalidetektering för Wazuh-loggar.
Analyserar loggmönster och identifierar avvikelser.
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')


def load_alerts(filepath: str) -> pd.DataFrame:
    """Ladda och formatera larmdata från Wazuh-export."""
    with open(filepath) as f:
        data = json.load(f)

    records = []
    for hit in data['hits']['hits']:
        src = hit['_source']
        records.append({
            'timestamp': src.get('timestamp', ''),
            'rule_id': src.get('rule', {}).get('id', 0),
            'rule_level': src.get('rule', {}).get('level', 0),
            'description': src.get('rule', {}).get('description', ''),
            'src_ip': src.get('data', {}).get('srcip', 'unknown'),
            'dst_port': src.get('data', {}).get('dstport', 0),
            'agent': src.get('agent', {}).get('name', 'unknown'),
        })

    df = pd.DataFrame(records)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df


def extract_features(df: pd.DataFrame, window: str = '1h') -> pd.DataFrame:
    """Extrahera tidsbaserade features för anomalidetektering."""
    df = df.set_index('timestamp').sort_index()

    features = df.resample('5min').agg(
        event_count=('rule_id', 'count'),
        unique_rules=('rule_id', 'nunique'),
        avg_severity=('rule_level', 'mean'),
        max_severity=('rule_level', 'max'),
        unique_ips=('src_ip', 'nunique'),
        unique_ports=('dst_port', 'nunique'),
    ).fillna(0)

    # Tidsbaserade features
    features['hour'] = features.index.hour
    features['is_night'] = features['hour'].apply(lambda h: 1 if h < 6 or h > 22 else 0)

    # Rolling-statistik (glidande medelvärde)
    features['event_count_rolling_mean'] = features['event_count'].rolling(6, min_periods=1).mean()
    features['event_count_rolling_std'] = features['event_count'].rolling(6, min_periods=1).std().fillna(0)

    # Z-score för antal händelser
    mean = features['event_count'].mean()
    std = features['event_count'].std()
    features['event_count_zscore'] = (features['event_count'] - mean) / (std if std > 0 else 1)

    return features


def detect_anomalies(features: pd.DataFrame, contamination: float = 0.1) -> pd.DataFrame:
    """Kör Isolation Forest för att hitta anomalier."""
    feature_cols = ['event_count', 'unique_rules', 'avg_severity',
                    'max_severity', 'unique_ips', 'unique_ports',
                    'is_night', 'event_count_zscore']

    X = features[feature_cols].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Isolation Forest — unsupervised anomalidetektering
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42
    )
    features['anomaly'] = model.fit_predict(X_scaled)
    features['anomaly_score'] = model.decision_function(X_scaled)

    # -1 = anomali, 1 = normal
    features['is_anomaly'] = features['anomaly'] == -1

    return features


def statistical_baseline(features: pd.DataFrame, threshold_sigma: float = 2.0) -> pd.DataFrame:
    """Enklare statistisk metod: flagga perioder med z-score over tröskelvärde."""
    features['stat_anomaly'] = abs(features['event_count_zscore']) > threshold_sigma
    return features


def generate_report(features: pd.DataFrame) -> str:
    """Generera en sammanfattande rapport."""
    anomalies = features[features['is_anomaly']]
    stat_anomalies = features[features['stat_anomaly']]

    report = []
    report.append("=" * 60)
    report.append("  ANOMALIDETEKTERINGSRAPPORT")
    report.append("=" * 60)
    report.append(f"\nAnalyserad period: {features.index.min()} — {features.index.max()}")
    report.append(f"Antal tidsperioder analyserade: {len(features)}")
    report.append(f"\n--- Isolation Forest ---")
    report.append(f"Anomalier detekterade: {len(anomalies)}")
    report.append(f"\n--- Statistisk baslinje (z-score) ---")
    report.append(f"Anomalier detekterade: {len(stat_anomalies)}")

    if len(anomalies) > 0:
        report.append(f"\n--- Detaljerad anomalidata ---")
        for idx, row in anomalies.iterrows():
            report.append(
                f"  {idx}: {int(row['event_count'])} händelser, "
                f"severity snitt {row['avg_severity']:.1f}, "
                f"{int(row['unique_ips'])} unika IP:n, "
                f"score {row['anomaly_score']:.3f}"
            )

    report.append("\n" + "=" * 60)
    return "\n".join(report)


if __name__ == '__main__':
    import sys

    filepath = sys.argv[1] if len(sys.argv) > 1 else 'baseline_alerts.json'
    print(f"Laddar data från {filepath}...")

    df = load_alerts(filepath)
    print(f"Laddade {len(df)} händelser")

    features = extract_features(df, window='1h')
    print(f"Extraherade features för {len(features)} tidsperioder")

    features = detect_anomalies(features)
    features = statistical_baseline(features)

    report = generate_report(features)
    print(report)

    # Spara resultat
    features.to_csv('anomaly_results.csv')
    with open('anomaly_report.txt', 'w') as f:
        f.write(report)

    print("\nResultat sparade till anomaly_results.csv och anomaly_report.txt")
