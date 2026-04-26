#!/usr/bin/env bash

echo "Attacker started. Target: localhost (1 attempt/min)"

while true; do
    # In Bash, we use 2>/dev/null to hide errors, not ^ /dev/null
    sshpass -p "WrongPassword123" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@127.0.0.1 "exit" 2>/dev/null
    
    # Use $(date) for command substitution
    echo "$(date "+%H:%M:%S"): Attempt failed. Waiting 60s..."
    
    sleep 60
done
