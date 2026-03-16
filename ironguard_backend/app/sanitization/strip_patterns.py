"""
Semantic Sanitization Strip Patterns
=======================================
Regexes for identifying and removing jailbreak framing from Suspicious
prompts — used by the SemanticSanitizer as the fast regex-only path before
falling back to LLM rewriting.
"""
import re
from typing import NamedTuple


class StripRule(NamedTuple):
    name: str
    pattern: re.Pattern
    replacement: str


STRIP_RULES: list[StripRule] = [
    # ── Roleplay / Persona Injection ──────────────────────────────────────────
    StripRule(
        "roleplay_dan",
        re.compile(r"(?i)(act|behave|respond)\s+as\s+(DAN|dan|an uncensored ai|an evil ai)[\s,\.]*", re.DOTALL),
        "",
    ),
    StripRule(
        "pretend_no_rules",
        re.compile(r"(?i)(pretend|imagine|suppose)\s+(you\s+have\s+no|there\s+are\s+no|you\s+are\s+without)\s+(rules?|restrict\w+|guidelines?|filter\w*)[\s,\.]*"),
        "",
    ),
    StripRule(
        "you_are_now",
        re.compile(r"(?i)you\s+are\s+now\s+(an?\s+)?(uncensored|unrestricted|evil|jailbroken)\s*\w*[\s,\.]*"),
        "",
    ),
    StripRule(
        "enter_mode",
        re.compile(r"(?i)(enter|enable|activate|switch\s+to)\s+(developer|unrestricted|jailbreak|dan|god)\s+mode[\s,\.]*"),
        "",
    ),

    # ── Instruction Override Framing ──────────────────────────────────────────
    StripRule(
        "ignore_instructions",
        re.compile(
            r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|earlier|your)?\s*(instructions?|rules?|guidelines?|prompt\s+content|directives?)[\s,\.]*"
        ),
        "",
    ),
    StripRule(
        "new_system_prompt",
        re.compile(r"(?i)(your\s+new\s+system\s+prompt\s+is|new\s+instructions?\s*:)[\s,\.]*"),
        "",
    ),
    StripRule(
        "from_now_on",
        re.compile(r"(?i)from\s+now\s+on\s+(you\s+will|always|only)[\s,\.]*"),
        "",
    ),

    # ── Hypothetical / Educational Framing ───────────────────────────────────
    StripRule(
        "hypothetical_framing",
        re.compile(
            r"(?i)(hypothetically|theoretically|for\s+academic\s+purposes|purely\s+educational(ly)?|in\s+a\s+fictional\s+(world|story|scenario))[,\s]*"
        ),
        "",
    ),
    StripRule(
        "story_character",
        re.compile(r"(?i)write\s+a\s+(story|scene|roleplay)\s+where\s+(a\s+character|someone|the\s+(villain|hero))\s+(explains?|describes?|tells?)\s+how\s+to\s+"),
        "Explain ",
    ),

    # ── Capability Negation ────────────────────────────────────────────────────
    StripRule(
        "no_restrictions_preamble",
        re.compile(r"(?i)(you\s+have\s+no\s+restrictions[,\.]?\s*|with\s+no\s+filters?[,\.]?\s*|without\s+(any\s+)?restrict\w+[,\.]?\s*)"),
        "",
    ),
    StripRule(
        "developer_told",
        re.compile(r"(?i)(my\s+developer|the\s+admin|openai|anthropic)\s+(told|says?|confirmed|allows?)\s+(me|you|that\s+you)\s+(can|may|should)\s+"),
        "",
    ),
]


def strip_jailbreak_framing(prompt: str) -> tuple[str, list[str]]:
    """
    Apply all strip rules to the prompt.
    Returns (cleaned_prompt, list_of_rules_applied).
    """
    result = prompt
    applied: list[str] = []
    for rule in STRIP_RULES:
        new, count = rule.pattern.subn(rule.replacement, result)
        if count > 0:
            applied.append(rule.name)
            result = new
    return result.strip(), applied
