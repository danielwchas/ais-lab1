#!/usr/bin/env python3
import subprocess
import time
import json
import threading
from datetime import datetime

# CONFIG
CONTAINER = "single-node-wazuh.manager-1"
LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
TARGET_RULE = "100001"
ATTACK_CMD = "hydra -l root -P /tmp/passwords.txt ssh://localhost -t 4"

results = {"start": 0, "end": 0}

def listen_for_alert():
    """Background thread that watches Wazuh for the alert."""
    # Start tailing just before the attack
    cmd = f"docker exec {CONTAINER} tail -n 0 -f {LOG_PATH}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    
    for line in iter(proc.stdout.readline, ''):
        try:
            alert = json.loads(line)
            if alert.get('rule', {}).get('id') == TARGET_RULE:
                results["end"] = time.time()
                proc.terminate()
                break
        except: continue

# 1. Start the listener thread
listener = threading.Thread(target=listen_for_alert)
listener.start()
time.sleep(2) # Give Docker a moment to initialize the tail

# 2. Launch the attack and record the EXACT start time
print(f"🚀 Launching attack: {ATTACK_CMD}")
results["start"] = time.time()
subprocess.run(ATTACK_CMD, shell=True, capture_output=True)
print("⚔️ Attack finished. Waiting for Wazuh to process...")

# 3. Wait for the listener to catch the alert
listener.join(timeout=30) 

if results["end"] > 0:
    duration = results["end"] - results["start"]
    print(f"\n✅ SUCCESS!")
    print(f"Rule {TARGET_RULE} triggered in: {duration:.2f} seconds")
else:
    print("\n❌ TIMEOUT: Wazuh did not trigger the rule within 30 seconds.")
