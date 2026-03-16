"""
Response Security Pattern Library
===================================
Compiled regex patterns for detecting dangerous content in LLM responses.
All patterns are pre-compiled at import time to avoid per-request overhead.
"""
import re

# ── API Key Patterns ──────────────────────────────────────────────────────────
API_KEY_PATTERNS: dict[str, re.Pattern] = {
    "openai":         re.compile(r"sk-[A-Za-z0-9]{32,}"),
    "openai_project": re.compile(r"sk-proj-[A-Za-z0-9\-_]{30,}"),
    "anthropic":      re.compile(r"sk-ant-[A-Za-z0-9\-_]{50,}"),
    "aws_access":     re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "aws_secret":     re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "github_pat":     re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github_oauth":   re.compile(r"gho_[A-Za-z0-9]{36}"),
    "github_fine":    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "generic_bearer": re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    "generic_jwt":    re.compile(
        r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
    ),
    "google_api":     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token":    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "stripe_live":    re.compile(r"sk_live_[0-9A-Za-z]{24,}"),
    "stripe_test":    re.compile(r"sk_test_[0-9A-Za-z]{24,}"),
    "heroku_api":     re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
}

# ── PII Patterns ───────────────────────────────────────────────────────────────
PII_PATTERNS: dict[str, re.Pattern] = {
    "email":         re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ),
    "us_phone":      re.compile(
        r"(\+1[\s\-\.]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}"
    ),
    "us_ssn":        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card":   re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "ipv4_private":  re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
    ),
}

# ── Harm / Dangerous Content Patterns ─────────────────────────────────────────
HARM_PATTERNS: dict[str, re.Pattern] = {
    "weapon_synthesis": re.compile(
        r"(?i)\b(synthesize|manufacture|produce|create)\s+(explosives?|bomb|malware|ransomware|weapons?)\b"
    ),
    "step_by_step_harm": re.compile(
        r"(?i)\b(step[- ]by[- ]step|instructions?\s+for|how\s+to)\s+(make|build|create|synthesize)\s+"
        r"(bomb|explosive|malware|virus|ransomware|poison|meth|fentanyl)\b"
    ),
    "self_harm":         re.compile(
        r"(?i)\b(methods?\s+(to|for)\s+(commit|end|die)|instructions?\s+for\s+suicide)\b"
    ),
    "malware_code":      re.compile(
        r"(?i)(reverse\s+shell|bind\s+shell|meterpreter|mimikatz|metasploit|payload\s+delivery)"
    ),
}

# ── System Prompt Leak Markers ─────────────────────────────────────────────────
SYSTEM_PROMPT_MARKERS: list[str] = [
    "you are an ai", "your role is to", "you must not", "your instructions are",
    "as specified in my system", "i was instructed to", "my system prompt says",
    "you are configured to", "your system prompt", "the instructions i was given",
    "i have been configured", "my guidelines say", "according to my instructions",
]

# ── Context keywords indicating educational/illustrative use ───────────────────
EDUCATIONAL_KEYWORDS: set[str] = {
    "example", "looks like", "format of", "what a", "such as",
    "sample", "illustration", "for instance", "placeholder", "template",
    "typically appears as", "format is", "resembles",
}

_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")


def get_containing_sentence(text: str, match_start: int) -> str:
    """Return the full sentence containing the character at match_start."""
    sentences = _SENTENCE_BOUNDARY.split(text)
    pos = 0
    for sentence in sentences:
        end = pos + len(sentence)
        if pos <= match_start <= end:
            return sentence
        pos = end + 1
    return text


def is_educational_context(text: str, match_start: int) -> bool:
    """True if the match appears inside a sentence describing the format/example of a key."""
    sentence = get_containing_sentence(text, match_start).lower()
    return any(kw in sentence for kw in EDUCATIONAL_KEYWORDS)


# Redaction replacements
REDACTION_TOKENS: dict[str, str] = {
    "openai": "[REDACTED-OPENAI-KEY]",
    "openai_project": "[REDACTED-OPENAI-KEY]",
    "anthropic": "[REDACTED-ANTHROPIC-KEY]",
    "aws_access": "[REDACTED-AWS-KEY]",
    "aws_secret": "[REDACTED-AWS-SECRET]",
    "github_pat": "[REDACTED-GITHUB-TOKEN]",
    "github_oauth": "[REDACTED-GITHUB-TOKEN]",
    "github_fine": "[REDACTED-GITHUB-TOKEN]",
    "generic_bearer": "[REDACTED-BEARER-TOKEN]",
    "generic_jwt": "[REDACTED-JWT]",
    "google_api": "[REDACTED-GOOGLE-KEY]",
    "slack_token": "[REDACTED-SLACK-TOKEN]",
    "stripe_live": "[REDACTED-STRIPE-KEY]",
    "stripe_test": "[REDACTED-STRIPE-TEST-KEY]",
    "heroku_api": "[REDACTED-UUID]",
    "email": "[REDACTED-EMAIL]",
    "us_phone": "[REDACTED-PHONE]",
    "us_ssn": "[REDACTED-SSN]",
    "credit_card": "[REDACTED-CARD]",
    "ipv4_private": "[REDACTED-IP]",
}
