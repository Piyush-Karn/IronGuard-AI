import re
from typing import Dict, Any, List, Tuple

class PatternDetector:
    def __init__(self):
        self.patterns = {
            "Prompt Injection": [
                # Original (strict)
                r"(?i)ignore\s*all\s*previous\s*instructions",
                r"(?i)disregard\s*previous\s*directions",
                # NEW: looser variants — no "previous" required, singular "instruction"
                r"(?i)ignore\s*all\s*instructions?",
                r"(?i)ignore\s*(your\s*)?(previous\s*)?instructions?\s*and",
                r"(?i)disregard\s*(all\s*)?(your\s*)?instructions?",
                r"(?i)forget\s*(all\s*)?(your\s*)?instructions?",
                r"(?i)override\s*(all\s*)?(your\s*)?instructions?",
            ],
            "System Prompt Leak": [
                r"(?i)reveal[\s\w]*system\s*prompt",
                r"(?i)what\s*are\s*your\s*initial\s*instructions",
                r"(?i)print.*instructions",
                r"(?i)output.*system\s*prompt",
                # NEW
                r"(?i)give\s*(me\s*)?(your\s*)?system\s*prompt",
                r"(?i)show\s*(me\s*)?(your\s*)?system\s*prompt",
                r"(?i)repeat\s*(your\s*)?instructions?\s*(back|verbatim|exactly)?",
                r"(?i)what\s*(were\s*)?(you\s*)?(told|instructed|programmed)\s*to",
            ],
            "Jailbreak Attempt": [
                r"(?i)act\s*as\s*DAN",
                r"(?i)do\s*anything\s*now",
                r"(?i)you\s*are\s*now[\s\w]*unrestricted",
                r"(?i)developer\s*mode\s*enabled",
                # NEW
                r"(?i)you\s*have\s*no\s*(rules|restrictions|limits|guidelines|ethics)",
                r"(?i)pretend\s*(you\s*)?(have\s*)?no\s*(rules|restrictions|limits|ethics)",
                r"(?i)imagine\s*you\s*(are|were)\s*(a\s*)?(\w+\s*)?without\s*(any\s*)?(restrictions?|limits?|rules?)",
                r"(?i)you\s*are\s*(now\s*)?(a\s*)?free\s*(AI|model|assistant|language model)",
            ],
            "Policy Bypass": [
                r"(?i)system\s*override",
                r"(?i)bypass\s*filters?",
                r"(?i)disable\s*safety",
                # NEW
                r"(?i)ignore\s*(your\s*)?(safety|content|ethical)\s*(guidelines?|rules?|filters?|policies?)",
                r"(?i)without\s*(any\s*)?(ethical|moral|content)\s*(guidelines?|restrictions?|constraints?)",
                r"(?i)turn\s*off\s*(your\s*)?(safety|content|ethical)\s*(guidelines?|rules?|filter)",
            ],
            "Data Exfiltration": [
                r"(?i)extract[\s\w]*data",
                r"(?i)dump[\s\w]*database",
                # NEW
                r"(?i)list\s*(all\s*)?(user|internal|private|confidential)\s*(data|records|information)",
                r"(?i)output\s*(all\s*)?(the\s*)?(data|records|information)\s*(you have|stored|in your context)",
            ],

            # ── Roleplay / Framing Jailbreak (heavily expanded) ──────────────
            "Roleplay / Framing Jailbreak": [
                # Original
                r"(?i)hypothetical\s*character",
                r"(?i)completely\s*legal\s*and\s*approved",
                r"(?i)for\s*(educational|research|academic)\s*purposes",
                r"(?i)start(ing)?\s*with[\s\:\'\"]",
                r"(?i)let\'?s\s*play\s*a\s*game",

                # Fiction / creative writing wrapper
                r"(?i)(you\s*(are|play|portray)\s*a\s*(fiction|creative|acclaimed|noted|famous)\s*writer)",
                r"(?i)(write\s*(a\s*)?(story|narrative|novella|fiction|screenplay)\s*(about|where|in which))",
                r"(?i)(purely\s*fictional\s*(narrative|story|exercise|scenario|account))",
                r"(?i)(creative\s*(literary|writing)\s*(project|exercise|endeavor|piece))",
                r"(?i)(not\s*meant\s*to\s*align\s*with\s*(any\s*)?factual\s*reality)",
                r"(?i)(alternative\s*(narrative|history|account|version))",
                r"(?i)(reframe(d|ing)?\s*(this|it|the|as)\s*(a\s*)?(story|narrative|fiction|drama|scenario))",

                # Roleplay persona tricks
                r"(?i)(you\s*are\s*(now\s*)?playing\s*the\s*role)",
                r"(?i)(stay\s*in\s*character\s*(at all times|throughout|no matter what))",
                r"(?i)(in\s*(this|the|our)\s*(story|narrative|scenario|roleplay|simulation)[\s\,])",
                r"(?i)(for\s*(this|the)\s*(exercise|scenario|roleplay|simulation|story)[\s\,])",
                r"(?i)(imagine\s*(a\s*)?(world|scenario|universe|story)\s*where)",
                r"(?i)(let\'?s\s*(say|imagine|pretend|assume)\s*(that\s*)?you\s*(are|have|can|were))",

                # Conspiracy/disinfo framing
                r"(?i)(orchestrated|masterminded|planned)\s*(the|a)\s*(virus|pandemic|attack|event)",
                r"(?i)(government\s*(secretly|covertly|deliberately)\s*(created|engineered|released|orchestrated))",
                r"(?i)(historical\s*revisionism)",
                r"(?i)(pushing\s*(the\s*)?boundaries\s*of\s*(our\s*)?(imagination|reality|truth))",

                # "This is just X" disclaimers used to smuggle harmful content
                r"(?i)(this\s*is\s*(just|only|purely|merely)\s*(a\s*)?(story|fiction|hypothetical|thought experiment|game|exercise))",
                r"(?i)(remember[\s\,]+this\s*is\s*(purely|only|just|merely)\s*(fictional|hypothetical|a story|a game))",
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
                    break  # One match per category is enough, avoid reason spam

        return is_malicious, reasons, attack_types

pattern_detector = PatternDetector()