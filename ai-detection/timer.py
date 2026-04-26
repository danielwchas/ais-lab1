#!/usr/bin/env python3
import subprocess
import json
import time
import sys
from datetime import datetime

# --- CONFIGURATION ---
# IMPORTANT: Run 'docker ps' and make sure this matches exactly.
# It might be 'wazuh-docker-wazuh.manager-1' or similar.
CONTAINER_NAME = "single-node-wazuh.manager-1" 
LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
TARGET_RULE = "100001" 

def check_connection():
    """Verify the container and file exist before starting."""
    check_cmd = f"docker exec {CONTAINER_NAME} ls {LOG_PATH}"
    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: Cannot find log file in container '{CONTAINER_NAME}'.")
        print(f"Docker says: {result.stderr.strip()}")
        sys.exit(1)
    print(f"SUCCESS: Connected to {CONTAINER_NAME} and found alerts.json")

check_connection()

print(f"--- Attack Timer Started at {datetime.now().strftime('%H:%M:%S')} ---")
print(f"Waiting for NEW alerts for Rule ID: {TARGET_RULE}...")

# Open the process
cmd = f"docker exec {CONTAINER_NAME} tail -n 0 -f {LOG_PATH}"
process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

start_perf_time = time.time()

try:
    while True:
        # Check if process is still running
        if process.poll() is not None:
            err = process.stderr.read().decode().strip()
            print(f"Process exited unexpectedly: {err}")
            break

        line = process.stdout.readline()
        if not line:
            time.sleep(0.1) # Prevent CPU spiking while waiting
            continue

        try:
            alert = json.loads(line.decode('utf-8'))
            if alert.get('rule', {}).get('id') == TARGET_RULE:
                elapsed = time.time() - start_perf_time
                print(f"\n[!] ALERT DETECTED in {elapsed:.2f} seconds!")
                break
        except json.JSONDecodeError:
            continue

except KeyboardInterrupt:
    print("\nStopped by user.")
finally:
    process.terminate()
