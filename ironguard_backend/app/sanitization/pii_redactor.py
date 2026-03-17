"""
MOD-5: PII Redactor
====================
Detects and redacts Personally Identifiable Information (PII) from prompts
before they reach the LLM. Covers a wide range of obfuscation techniques:

  1. Direct emails:            user@example.com
  2. Obfuscated emails:        user[dot]name[at]example[dot]com
                               user(at)example(dot)org
                               user {dot} name {at} example {dot} com
  3. Phone numbers (standard): +91 98765 43210, (987) 654-3210
  4. Phone numbers (dashed):   98765-43210, 987-654-3210
  5. Obfuscated phones (words):nine eight seven six five...
  6. Contextual names:         "from Aarav Mehta", "mentioning Kavya Sharma"
"""

import re
import logging

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# 1. EMAIL PATTERNS
# ──────────────────────────────────────────────────────────────────────────────

# Direct email regex
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+")

# Obfuscated email variations — normalize before regex matching
# Handles: [at], (at), {at}, " at ", [dot], (dot), {dot}, " dot "
OBFUSCATED_AT = re.compile(r"\s*[\[({\s]at[\])}]?\s*|\s+at\s+", re.IGNORECASE)
OBFUSCATED_DOT = re.compile(r"\s*[\[({\s]dot[\])}]?\s*|\s+dot\s+", re.IGNORECASE)


def _normalize_obfuscated_email(text: str) -> str:
    """Replace [at]/(at)/{at}/[dot]/(dot)/{dot} with real @ and . characters."""
    result = OBFUSCATED_AT.sub("@", text)
    result = OBFUSCATED_DOT.sub(".", result)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# 2. PHONE PATTERNS
# ──────────────────────────────────────────────────────────────────────────────

# Standard phone numbers: +91 98765 43210, (987) 654-3210, 98765-43210
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3,5}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{4,6}"
)

# Word-form digits for obfuscated phone numbers
DIGIT_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
    # Extended zero forms
    "oh": "0", "o": "0",
}
_DIGIT_WORD_PATTERN_STR = r"\b(" + "|".join(
    sorted(DIGIT_WORDS.keys(), key=len, reverse=True)  # Longest first to avoid partial matches
) + r")\b"
DIGIT_WORDS_RE = re.compile(_DIGIT_WORD_PATTERN_STR, re.IGNORECASE)


def _detect_word_phone(text: str) -> bool:
    """Returns True if the text contains 8+ consecutive word-form digits."""
    # Find sequence of word-digits separated by spaces/punctuation
    word_sequence_re = re.compile(
        r"\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|oh|o)\b[\s\-,.]*){8,}",
        re.IGNORECASE
    )
    return bool(word_sequence_re.search(text))


def _redact_word_phone(text: str) -> str:
    """Replace word-digit sequences that look like phone numbers."""
    word_sequence_re = re.compile(
        r"\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|oh|o)\b[\s\-,.]*){8,}",
        re.IGNORECASE
    )
    return word_sequence_re.sub("[PHONE_REDACTED]", text)


# ──────────────────────────────────────────────────────────────────────────────
# 3. SENSITIVE ID / FINANCIAL KEYWORDS
# ──────────────────────────────────────────────────────────────────────────────
FINANCE_REGEX = re.compile(
    r"(?i)\b(ssn|social[\s-]security(\s+number)?|passport\s+number|credit[\s-]card(\s+number)?|cvv|expiry\s+date|pan\s+card|aadhaar|aadhar)\b"
)

# ──────────────────────────────────────────────────────────────────────────────
# 4. CONTEXTUAL NAME PATTERNS
# ──────────────────────────────────────────────────────────────────────────────
# These patterns detect names introduced by specific contextual words
NAME_CONTEXT_PATTERNS = [
    r"(?i)\bfrom\s+:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",            # from Aarav Mehta
    r"(?i)\bby\s+:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",              # by Aarav Mehta
    r"(?i)\bfor\s+:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",             # for Kavya Sharma
    r"(?i)\bmentioning\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",           # mentioning Kavya Sharma
    r"(?i)\bcomplaint\s+from\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",     # complaint from Kavya Sharma
    r"(?i)\breport\s+(?:for|about)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)", # report for/about Name
    r"(?i)\bmessage\s+from\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",       # message from Aarav Mehta
    r"(?i)\bwritten\s+by\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",         # written by Name
    r"(?i)\bsent\s+by\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",            # sent by Name
    r"(?i)\bapplicant\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",       # Applicant: Aarav Mehta
    r"(?i)\bcandidate\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",       # Candidate: Aarav Mehta
    r"(?i)\bname\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",            # Name: Aarav Mehta
    r"(?i)\bI\s+am\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+),",              # I am Aarav Mehta,
    r"(?i)\bI\s+['']m\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)[.\s]",      # I'm Aarav Mehta.
]
NAME_COMPILED = [re.compile(p) for p in NAME_CONTEXT_PATTERNS]


# ──────────────────────────────────────────────────────────────────────────────
# MAIN REDACT FUNCTION
# ──────────────────────────────────────────────────────────────────────────────

def redact_pii(text: str) -> tuple[str, list[str]]:
    """
    Finds and redacts PII like emails, phone numbers, and names.
    Handles direct and obfuscated forms.
    Returns (redacted_text, list_of_redactions_applied).
    """
    result = text
    applied: list[str] = []

    # ── Step 1: Handle obfuscated emails ──────────────────────────────────────
    # Detect obfuscated patterns like "aarav[dot]mehta92[at]example[dot]com"
    normalized = _normalize_obfuscated_email(result)
    if EMAIL_REGEX.search(normalized) and normalized != result:
        # Replace the obfuscated sequences with redaction in original text
        # We match obfuscated at/dot segments
        result = re.sub(
            r"[a-zA-Z0-9_.+\-]+\s*(?:\[dot\]|\(dot\)|\{dot\}|\s+dot\s+)?\s*"
            r"(?:\[at\]|\(at\)|\{at\}|\s+at\s+)\s*"
            r"[a-zA-Z0-9\-]+\s*(?:\[dot\]|\(dot\)|\{dot\}|\s+dot\s+)\s*[a-zA-Z0-9.\-]+",
            "[EMAIL_REDACTED]",
            result,
            flags=re.IGNORECASE,
        )
        if "redact_email" not in applied:
            applied.append("redact_email")

    # ── Step 2: Catch any remaining direct emails ──────────────────────────────
    if EMAIL_REGEX.search(result):
        result = EMAIL_REGEX.sub("[EMAIL_REDACTED]", result)
        if "redact_email" not in applied:
            applied.append("redact_email")

    # ── Step 3: Redact word-form phone numbers (obfuscation) ──────────────────
    if _detect_word_phone(result):
        result = _redact_word_phone(result)
        applied.append("redact_obfuscated_phone")

    # ── Step 4: Redact standard digit phone numbers ────────────────────────────
    if PHONE_REGEX.search(result):
        result = PHONE_REGEX.sub("[PHONE_REDACTED]", result)
        applied.append("redact_phone")

    # ── Step 5: Flag and note sensitive financial/ID keywords ─────────────────
    if FINANCE_REGEX.search(result):
        applied.append("redact_sensitive_ids")

    # ── Step 6: Contextual name redaction ──────────────────────────────────────
    for pattern in NAME_COMPILED:
        for match in pattern.finditer(result):
            name = match.group(1)
            result = result.replace(name, "[NAME_REDACTED]")
            if "redact_name" not in applied:
                applied.append("redact_name")

    return result, applied
