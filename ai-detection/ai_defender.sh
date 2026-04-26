#!/usr/bin/env bash

# Config
API_URL="https://localhost:55000"
INDEXER_URL="https://localhost:9200"
API_USER="wazuh-wui"
API_PASS="MyS3cr37P450r.*-"
INDEXER_AUTH="admin:SecretPassword"

while true; do
    echo "--- Cycle Start: $(date "+%H:%M:%S") ---"

    # 1. Fetch 12h for AI context
    curl -k -u "$INDEXER_AUTH" -s -X GET "$INDEXER_URL/wazuh-alerts-*/_search?size=1000" \
         -H 'Content-Type: application/json' \
         -d '{"query": {"range": {"timestamp": {"gte": "now-12h"}}}}' > baseline_alerts.json

    # 2. Analyze
    python3 anomaly_detector.py baseline_alerts.json
    python3 alert_manager.py

    # 3. FRESHNESS FILTER (The part that was missing!)
    IS_FRESH_ANOMALY=$(python3 -c "
import pandas as pd
from datetime import datetime, timedelta
try:
    # Use the results from anomaly_detector.py
    df = pd.read_csv('anomaly_results.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp']).dt.tz_localize(None)
    
    # Check if any anomaly is newer than 10 minutes ago
    # We use 10m to account for the 5m sleep + processing time
    cutoff = datetime.utcnow() - timedelta(minutes=10)
    recent = df[(df['is_anomaly'] == True) & (df['timestamp'] > cutoff)]
    print(not recent.empty)
except Exception as e:
    print('False')
" 2>/dev/null)

    if [ "$IS_FRESH_ANOMALY" = "True" ]; then
        echo "--- Fresh Anomaly Detected! Reporting... ---"
        TOKEN=$(curl -u "$API_USER:$API_PASS" -k -s -X GET "$API_URL/security/user/authenticate" | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['token'])")
        
        if [ -n "$TOKEN" ]; then
            PAYLOAD='{"events": ["{\"ai_detector\": \"true\", \"severity\": \"critical\", \"description\": \"AI-anomalidetektering: NYTT mönster identifierat\"}"]}'
            RESPONSE=$(curl -k -s -X POST "$API_URL/events" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$PAYLOAD")
            echo "Manager Response: $RESPONSE"
        fi
    else
        echo "No NEW anomalies in the last 10 minutes. Standing by."
    fi

    echo "Waiting 5m..."
    sleep 300
done