#!/usr/bin/env python3
import time
import json
from datetime import datetime

results = {
    'test_scenario': 'SSH brute force + portskanning + filändring',
    'tests': []
}

# Simulera mätning (ersätt med faktiska mätningar från din miljö)
test_cases = [
    {
        'attack': 'SSH brute force (10 försök)',
        'rule_based_detection_sec': 3,
        'ai_detection_sec': 3,
        'rule_based_detected': True,
        'ai_detected': True,
    },
    {
        'attack': 'Portskanning (top 1000)',
        'rule_based_detection_sec': None,
        'ai_detection_sec': 5,
        'rule_based_detected': False,
        'ai_detected': True,
    },
    {
        'attack': 'Kritisk filändring',
        'rule_based_detection_sec': 24,
        'ai_detection_sec': 4,
        'rule_based_detected': True,
        'ai_detected': True,
        'percent_improved' : ((24-4)/24)*100
    },
    {
        'attack': 'Långsam brute force (1 försök/min)',
        'rule_based_detection_sec': None,
        'ai_detection_sec': 2,
        'rule_based_detected': False,
        'ai_detected': True,
    },
]

results['tests'] = test_cases
results['measurement_date'] = datetime.now().isoformat()

with open('detection_comparison.json', 'w') as f:
    json.dump(results, f, indent=2)
    
print("Mall skapad: detection_comparison.json")
print("Fyll i med dina faktiska mätresultat efter testning.")
print("\nFör VG: Beräkna procentuell förbättring:")
print("  Förbättring = (regelbaserad_tid - ai_tid) / regelbaserad_tid * 100")