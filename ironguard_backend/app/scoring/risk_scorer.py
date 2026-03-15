"""
Risk Scorer — aggregates signals from all three detectors.

Scoring weights:
  Regex pattern match          → +60  (known exact attack signatures)
  Semantic similarity hit      → +30  (vector proximity to known attacks)
  Classifier malicious intent  → +50  (contextual / novel attacks)

Max observable score:  140  (capped at 100 in the output)

Classification bands:
  0  – 29  → Safe
  30 – 59  → Suspicious   (action: Sanitize)
  60+      → Malicious    (action: Block)
"""

from app.models.schemas import RiskExplanation
from app.threat_detection.pattern import pattern_detector
from app.threat_detection.similarity import similarity_detector
from app.threat_detection.intent_classifier import ClassifierResult


class RiskScorer:
    def __init__(self):
        self.weights = {
            "pattern_match":   60,
            "vector_similarity": 30,
            "classifier_intent": 50,
            "guardrail_fail":   30,
        }

    def calculate_risk(
        self,
        prompt: str,
        guardrail_results: dict = None,
        classifier_result: ClassifierResult = None,
    ) -> RiskExplanation:

        score = 0
        reasons = []
        attack_types = set()

        # ── 1. Regex pattern detection ────────────────────────────────────────
        pat_malicious, pat_reasons, pat_types = pattern_detector.detect(prompt)
        if pat_malicious:
            score += self.weights["pattern_match"]
            reasons.extend(pat_reasons)
            attack_types.update(pat_types)

        # ── 2. Semantic similarity (ChromaDB) ─────────────────────────────────
        sim_suspicious, sim_reasons, sim_types = similarity_detector.detect(prompt)
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
            # Map classifier label → IronGuard attack taxonomy
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

        # ── 4. Guardrail integrations (stub / external) ───────────────────────
        if guardrail_results and not guardrail_results.get("safe", True):
            score += self.weights["guardrail_fail"]
            reasons.append(
                f"Guardrail violation: {guardrail_results.get('reason', 'Unknown')}"
            )
            attack_types.add("Policy Bypass")

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