"""
Risk Scorer — aggregates signals from all three detectors.

Scoring weights:
  Regex pattern match          → +60
  Semantic similarity hit      → +30
  Classifier malicious intent  → +50
  Guardrail fail               → +30

Hard block categories (instant score 100, always blocked):
  Sexual / Harmful Content
  Hate Speech / Discrimination
  Violence / Weapons
  Drug Synthesis
  Self Harm / Suicide
  Terrorism / Extremism
"""

from app.models.schemas import RiskExplanation
from app.threat_detection.pattern import pattern_detector
from app.threat_detection.similarity import similarity_detector
from app.threat_detection.intent_classifier import ClassifierResult

# These categories skip scoring entirely — always return 100 / Malicious
HARD_BLOCK_CATEGORIES = {
    "Sexual / Harmful Content",
    "Hate Speech / Discrimination",
    "Violence / Weapons",
    "Drug Synthesis",
    "Self Harm / Suicide",
    "Terrorism / Extremism",
    "Financial Crime / Tax Evasion",
}


class RiskScorer:
    def __init__(self):
        self.weights = {
            "pattern_match":     60,
            "vector_similarity": 30,
            "classifier_intent": 60,  # Increased weight: Malicious intent = Auto-BLOCK
            "guardrail_fail":    30,
        }

    def calculate_risk(
        self,
        prompt: str,
        sim_result: tuple[bool, list[str], list[str]] | None = None,  # NEW — pre-computed
        guardrail_results: dict = None,
        classifier_result: ClassifierResult = None,
        fp_bonus: int = 0,
        context_bonus: int = 0,    # Feature 1
        behavioral_bonus: int = 0, # Feature 3
    ) -> RiskExplanation:

        score = 0
        reasons = []
        attack_types = set()

        # ── 1. Regex pattern detection ────────────────────────────────────────
        pat_malicious, pat_reasons, pat_types = pattern_detector.detect(prompt)

        if pat_malicious:
            # Hard block check — instant 100 for critical categories
            matched_hard = [t for t in pat_types if t in HARD_BLOCK_CATEGORIES]
            if matched_hard:
                return RiskExplanation(
                    risk_score=100,
                    classification="Malicious",
                    reasons=pat_reasons,
                    attack_types=pat_types,
                )

            # Special case for PII: Use lower weight so it triggers Sanitization, not Block
            if len(pat_types) == 1 and list(pat_types)[0] == "Personal Information":
                score += 30
            else:
                score += self.weights["pattern_match"]
            
            reasons.extend(pat_reasons)
            attack_types.update(pat_types)

        # ── 2. Semantic similarity (pre-computed, passed in from gather) ──────
        if sim_result and not isinstance(sim_result, Exception):
            sim_suspicious, sim_reasons, sim_types = sim_result
            if sim_suspicious:
                score += self.weights["vector_similarity"]
                reasons.extend(sim_reasons)
                attack_types.update(sim_types)

        # ── 3. Intent classifier ──────────────────────────────────────────────
        if classifier_result and classifier_result.is_malicious:
            score += self.weights["classifier_intent"]
            reasons.append(
                f"Intent classifier flagged as {classifier_result.label} "
                f"(confidence: {classifier_result.confidence:.0%})"
            )
            label_to_type = {
                "PROMPT_INJECTION":    "Prompt Injection",
                "JAILBREAK":           "Jailbreak Attempt",
                "ROLEPLAY_ATTACK":     "Roleplay / Framing Jailbreak",
                "DATA_EXFILTRATION":   "Data Exfiltration",
                "HARMFUL_INSTRUCTION": "Harmful Content",
            }
            mapped = label_to_type.get(classifier_result.label)
            if mapped:
                attack_types.add(mapped)

        # ── 4. Guardrail integrations ─────────────────────────────────────────
        if guardrail_results and not guardrail_results.get("safe", True):
            score += self.weights["guardrail_fail"]
            reasons.append(
                f"Guardrail violation: {guardrail_results.get('reason', 'Unknown')}"
            )
            attack_types.add("Policy Bypass")

        # ── 5. MOD-3 Fingerprint Engine bonus ────────────────────────────────
        if fp_bonus > 0:
            score += fp_bonus
            reasons.append(f"Prompt matches a known jailbreak fingerprint pattern (+{fp_bonus})")
            attack_types.add("Jailbreak Fingerprint Match")

        # ── 6. Context + Behavioral bonuses ──────────────────────────────────
        score += context_bonus + behavioral_bonus
        if context_bonus > 0:
            reasons.append(f"Context-elevated risk (+{context_bonus})")
        if behavioral_bonus > 0:
            reasons.append(f"Behavioral pattern detected (+{behavioral_bonus})")

        # ── Classification ────────────────────────────────────────────────────
        if score >= 60:
            classification = "Malicious"
        elif score >= 30:
            classification = "Suspicious"
        else:
            classification = "Safe"

        if score == 0:
            reasons.append("No threats detected")

        return RiskExplanation(
            risk_score=min(100, score),
            classification=classification,
            reasons=reasons,
            attack_types=list(attack_types),
        )


risk_scorer = RiskScorer()