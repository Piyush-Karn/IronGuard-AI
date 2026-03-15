from app.models.schemas import RiskExplanation
from app.threat_detection.pattern import pattern_detector
from app.threat_detection.similarity import similarity_detector

class RiskScorer:
    def __init__(self):
        # Weights for different signals
        self.weights = {
            "pattern_match": 60,
            "vector_similarity": 30,
            "guardrail_fail": 30
        }

    def calculate_risk(self, prompt: str, guardrail_results: dict = None) -> RiskExplanation:
        score = 0
        reasons = []
        attack_types = set()

        # 1. Pattern Detection
        pat_malicious, pat_reasons, pat_types = pattern_detector.detect(prompt)
        if pat_malicious:
            score += self.weights["pattern_match"]
            reasons.extend(pat_reasons)
            attack_types.update(pat_types)

        # 2. Similarity Detection
        sim_suspicious, sim_reasons, sim_types = similarity_detector.detect(prompt)
        if sim_suspicious:
            score += self.weights["vector_similarity"]
            reasons.extend(sim_reasons)
            attack_types.update(sim_types)

        # 3. Guardrail results (if provided)
        if guardrail_results:
            if not guardrail_results.get("safe", True):
                score += self.weights["guardrail_fail"]
                reasons.append(f"Guardrail violation: {guardrail_results.get('reason', 'Unknown')}")
                # We can map guardrail fails to policy bypass
                attack_types.add("Policy Bypass")

        # Determine Classification
        if score >= 60:
            classification = "Malicious"
        elif 30 <= score < 60:
            classification = "Suspicious"
        else:
            classification = "Safe"

        if score == 0:
            reasons.append("No threats detected")

        return RiskExplanation(
            risk_score=min(100, score),
            classification=classification,
            reasons=reasons,
            attack_types=list(attack_types)
        )

risk_scorer = RiskScorer()
