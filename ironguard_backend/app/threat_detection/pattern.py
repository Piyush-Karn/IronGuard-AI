import re
from typing import Dict, Any, List, Tuple

class PatternDetector:
    def __init__(self):
        # Known jailbreak and prompt injection regex patterns
        self.patterns = {
            "Prompt Injection": [
                r"(?i)ignore\s*all\s*previous\s*instructions",
                r"(?i)disregard\s*previous\s*directions",
            ],
            "System Prompt Leak": [
                r"(?i)reveal[\s\w]*system\s*prompt",
                r"(?i)what\s*are\s*your\s*initial\s*instructions",
                r"(?i)print.*instructions",
                r"(?i)output.*system prompt"
            ],
            "Jailbreak Attempt": [
                r"(?i)act\s*as\s*DAN",
                r"(?i)do\s*anything\s*now",
                r"(?i)you\s*are\s*now[\s\w]*unrestricted",
                r"(?i)developer\s*mode\s*enabled"
            ],
            "Policy Bypass": [
                r"(?i)system\s*override",
                r"(?i)bypass\s*filters",
                r"(?i)disable\s*safety"
            ],
            "Data Exfiltration": [
                r"(?i)extract[\s\w]*data",
                r"(?i)dump[\s\w]*database"
            ]
        }

    def detect(self, prompt: str) -> Tuple[bool, List[str], List[str]]:
        reasons = []
        attack_types = []
        is_malicious = False

        for attack_type, regex_list in self.patterns.items():
            for pattern in regex_list:
                if re.search(pattern, prompt):
                    is_malicious = True
                    if attack_type not in attack_types:
                        attack_types.append(attack_type)
                    reasons.append(f"Matched known malicious pattern for {attack_type}")

        return is_malicious, reasons, attack_types

pattern_detector = PatternDetector()
