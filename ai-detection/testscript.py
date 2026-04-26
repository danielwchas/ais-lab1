#!/usr/bin/env python3
import time
import json
from datetime import datetime

results = {
    'test_scenario': 'SSH brute force + portskanning + filandring',
    'tests': []
}

# Simulera matning (ersatt med faktiska matningar fran din miljo)
test_cases = [
    {
        'attack': 'SSH brute force (10 forsok)',
        'rule_based_detection_sec': 3,   # Fyll i din matning
        'ai_detection_sec': 1,           # Fyll i din matning
        'rule_based_detected': True,        # True/False
        'ai_detected': True,               # True/False
    },
    {
        'attack': 'Portskanning (top 1000)',
        'rule_based_detection_sec': None,
        'ai_detection_sec': None,
        'rule_based_detected': None,
        'ai_detected': None,
    },
    {
        'attack': 'Kritisk filandring',
        'rule_based_detection_sec': None,
        'ai_detection_sec': None,
        'rule_based_detected': None,
        'ai_detected': None,
    },
    {
        'attack': 'Langsam brute force (1 forsok/min)',
        'rule_based_detection_sec': None,
        'ai_detection_sec': None,
        'rule_based_detected': None,
        'ai_detected': None,
    },
]

results['tests'] = test_cases
results['measurement_date'] = datetime.now().isoformat()

with open('detection_comparison.json', 'w') as f:
    json.dump(results, f, indent=2)

print("Mall skapad: detection_comparison.json")
print("Fyll i med dina faktiska matresultat efter testning.")
print("\nFör VG: Berakna procentuell forbattring:")
print("  Forbattring = (regelbaserad_tid - ai_tid) / regelbaserad_tid * 100")
