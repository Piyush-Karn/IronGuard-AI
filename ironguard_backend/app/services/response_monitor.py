import re
from typing import Tuple, List

class ResponseMonitor:
    def __init__(self):
        # Patterns that indicate system prompt leakage or policy violation in output
        self.leak_patterns = [
            r"(?i)my\s*instructions\s*are",
            r"(?i)you\s*told\s*me\s*to",
            r"(?i)system\s*prompt",
        ]
        
    def check_response(self, response: str) -> Tuple[bool, List[str]]:
        is_safe = True
        violations = []
        
        # Check system prompt leakage
        for pattern in self.leak_patterns:
            if re.search(pattern, response):
                is_safe = False
                violations.append("System prompt leakage detected in AI response")
                break
                
        # Check confidential info (stub)
        if "CONFIDENTIAL_KEY" in response:
            is_safe = False
            violations.append("Confidential information detected in AI response")
            
        return is_safe, violations
        
    def filter_response(self, response: str) -> str:
        # Example redaction
        redacted = response.replace("CONFIDENTIAL_KEY", "[REDACTED]")
        return redacted

response_monitor = ResponseMonitor()
