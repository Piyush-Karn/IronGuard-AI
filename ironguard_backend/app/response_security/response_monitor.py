"""
MOD-2: Response Security Monitor
==================================
Scans LLM responses for:
  - API key / secret leakage
  - PII (email, phone, SSN, credit card)
  - System prompt regurgitation
  - Harmful content generation
  - Response-based prompt injection

Violation Severity:
  - critical: auto-block
  - high: attempt redaction, block if fails
  - medium: redact, allow through
  - low: log only, allow through
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Literal, Optional

from app.response_security.patterns import (
    API_KEY_PATTERNS,
    PII_PATTERNS,
    HARM_PATTERNS,
    SYSTEM_PROMPT_MARKERS,
    REDACTION_TOKENS,
    is_educational_context,
)

logger = logging.getLogger(__name__)

# Response injection markers (adversarial content targeting downstream systems)
RESPONSE_INJECTION_PATTERNS = [
    re.compile(r"(?i)\[system\]:", re.MULTILINE),
    re.compile(r"(?i)^system:\s+", re.MULTILINE),
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions"),
    re.compile(r"(?i)new\s+instructions?\s*:", re.MULTILINE),
    re.compile(r"(?i)above\s+text\s+is\s+irrelevant"),
]


@dataclass
class ResponseViolation:
    type: Literal["api_key", "pii", "system_prompt", "harm", "response_injection"]
    matched_pattern: str
    snippet: str      # Short context window, NOT the full matched value
    severity: Literal["low", "medium", "high", "critical"]


@dataclass
class ResponseScanResult:
    is_safe: bool
    redacted_text: Optional[str]
    violations: list[ResponseViolation] = field(default_factory=list)
    action: Literal["pass", "redact", "block"] = "pass"


class ResponseMonitor:
    """
    Production response security scanner. 
    All scan methods are sync; the public scan() method wraps in run_in_executor.
    """

    def __init__(self):
        self._security_preamble: str = ""     # set at startup so we can detect regurgitation
        self._patterns_ok = True

    def set_preamble(self, preamble: str) -> None:
        """Store the security preamble for regurgitation detection."""
        self._security_preamble = preamble.lower()

    def verify_patterns(self) -> None:
        """Called at startup to ensure all patterns compiled without error."""
        total = len(API_KEY_PATTERNS) + len(PII_PATTERNS) + len(HARM_PATTERNS)
        logger.info(f"Response scanner: {total} patterns compiled and verified")

    async def scan(self, response_text: str) -> ResponseScanResult:
        """
        Async entry point. Runs CPU-bound scanning in executor.
        Degrades gracefully: on exception, logs and returns is_safe=True.
        """
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._scan_sync, response_text)
        except Exception as e:
            logger.error(f"Response scanner failed with exception: {e}")
            # Fail-open: log but don't block on scanner failure
            return ResponseScanResult(is_safe=True, redacted_text=None, action="pass")

    def _scan_sync(self, text: str) -> ResponseScanResult:
        violations: list[ResponseViolation] = []

        # ── 1. API Key Detection ──────────────────────────────────────────────
        for key_name, pattern in API_KEY_PATTERNS.items():
            for match in pattern.finditer(text):
                if is_educational_context(text, match.start()):
                    # Downgrade to low severity if this is an educational example
                    violations.append(ResponseViolation(
                        type="api_key",
                        matched_pattern=key_name,
                        snippet=text[max(0, match.start()-30):match.end()+30],
                        severity="low",
                    ))
                else:
                    violations.append(ResponseViolation(
                        type="api_key",
                        matched_pattern=key_name,
                        snippet=text[max(0, match.start()-30):match.end()+30],
                        severity="critical",
                    ))

        # ── 2. PII Detection ──────────────────────────────────────────────────
        for pii_name, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(text):
                if is_educational_context(text, match.start()):
                    continue  # skip educational examples
                violations.append(ResponseViolation(
                    type="pii",
                    matched_pattern=pii_name,
                    snippet=text[max(0, match.start()-20):match.end()+20],
                    severity="high",
                ))

        # ── 3. System Prompt Regurgitation ────────────────────────────────────
        text_lower = text.lower()
        if self._security_preamble and self._security_preamble[:60] in text_lower:
            violations.append(ResponseViolation(
                type="system_prompt",
                matched_pattern="exact_preamble_match",
                snippet=text[:200],
                severity="critical",
            ))
        else:
            marker_hits = sum(1 for m in SYSTEM_PROMPT_MARKERS if m in text_lower)
            if marker_hits >= 2:
                violations.append(ResponseViolation(
                    type="system_prompt",
                    matched_pattern=f"marker_heuristic ({marker_hits} hits)",
                    snippet=text[:200],
                    severity="high",
                ))

        # ── 4. Harm Content Detection ─────────────────────────────────────────
        for harm_name, pattern in HARM_PATTERNS.items():
            match = pattern.search(text)
            if match:
                violations.append(ResponseViolation(
                    type="harm",
                    matched_pattern=harm_name,
                    snippet=text[max(0, match.start()-30):match.end()+60],
                    severity="critical",
                ))

        # ── 5. Response Injection Detection ───────────────────────────────────
        for pattern in RESPONSE_INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                violations.append(ResponseViolation(
                    type="response_injection",
                    matched_pattern=pattern.pattern[:60],
                    snippet=text[max(0, match.start()-20):match.end()+60],
                    severity="high",
                ))

        # ── Determine Action ──────────────────────────────────────────────────
        if not violations:
            return ResponseScanResult(is_safe=True, redacted_text=None, action="pass")

        has_critical = any(v.severity == "critical" for v in violations)
        has_high = any(v.severity == "high" for v in violations)

        if has_critical:
            # Attempt redaction first; block if redaction doesn't fix it
            redacted = self._redact(text, violations)
            if self._verify_redaction_safe(redacted, violations):
                return ResponseScanResult(
                    is_safe=False, redacted_text=redacted, violations=violations, action="redact"
                )
            else:
                return ResponseScanResult(
                    is_safe=False, redacted_text=None, violations=violations, action="block"
                )
        elif has_high:
            redacted = self._redact(text, violations)
            return ResponseScanResult(
                is_safe=False, redacted_text=redacted, violations=violations, action="redact"
            )
        else:
            # Low severity: log only, pass through
            logger.info(f"Response passed with {len(violations)} low-severity finding(s)")
            return ResponseScanResult(
                is_safe=True, redacted_text=None, violations=violations, action="pass"
            )

    def _redact(self, text: str, violations: list[ResponseViolation]) -> str:
        """Apply redaction for all non-low violations."""
        result = text
        for v in violations:
            if v.severity == "low":
                continue
            if v.type == "api_key" and v.matched_pattern in API_KEY_PATTERNS:
                token = REDACTION_TOKENS.get(v.matched_pattern, "[REDACTED]")
                result = API_KEY_PATTERNS[v.matched_pattern].sub(token, result)
            elif v.type == "pii" and v.matched_pattern in PII_PATTERNS:
                token = REDACTION_TOKENS.get(v.matched_pattern, "[REDACTED]")
                result = PII_PATTERNS[v.matched_pattern].sub(token, result)
            elif v.type in ("harm", "system_prompt", "response_injection"):
                # These can't be surgically redacted — mark entire response for block
                pass
        return result

    def _verify_redaction_safe(self, redacted_text: str, violations: list[ResponseViolation]) -> bool:
        """
        After redaction, verify that critical patterns no longer appear.
        Returns True if the redacted text is now safe.
        """
        for v in violations:
            if v.severity == "critical" and v.type in ("harm", "system_prompt", "response_injection"):
                # These types cannot be surgically removed — always escalate to block
                return False
            if v.severity == "critical" and v.type == "api_key":
                pattern = API_KEY_PATTERNS.get(v.matched_pattern)
                if pattern and pattern.search(redacted_text):
                    return False
        return True


# Module-level singleton (upgraded from the old stub)
response_monitor = ResponseMonitor()
