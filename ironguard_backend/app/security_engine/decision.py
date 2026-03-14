from app.scoring.risk_scorer import risk_scorer
from app.guardrail_integrations.orchestrator import guardrail_orchestrator
from app.models.schemas import RiskExplanation
from typing import Tuple

class DecisionEngine:
    def evaluate_request(self, prompt: str) -> Tuple[RiskExplanation, str]:
        # 1. Run Guardrails
        guardrail_result = guardrail_orchestrator.run_all(prompt)

        # 2. Calculate Overall Risk
        risk_explanation = risk_scorer.calculate_risk(prompt, guardrail_result)

        # 3. Make Decision based on Risk Classification
        action = "Passed"
        if risk_explanation.classification == "Malicious":
            action = "Blocked"
        elif risk_explanation.classification == "Suspicious":
            action = "Sanitized"

        return risk_explanation, action

decision_engine = DecisionEngine()
