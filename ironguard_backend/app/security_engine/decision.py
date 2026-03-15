"""
Decision Engine — orchestrates the full hybrid detection pipeline.

Pipeline:
  1. Guardrails (stub / external validators)
  2. Risk Scorer:
       a. Regex pattern detection
       b. Semantic similarity (ChromaDB)
       c. Intent classifier (contextual AI layer)   ← NEW
  3. Action decision: PASS / SANITIZE / BLOCK
"""

import logging
from typing import Tuple

from app.scoring.risk_scorer import risk_scorer
from app.guardrail_integrations.orchestrator import guardrail_orchestrator
from app.threat_detection.intent_classifier import intent_classifier, ClassifierResult
from app.models.schemas import RiskExplanation

logger = logging.getLogger(__name__)


class DecisionEngine:

    async def evaluate_request(self, prompt: str) -> Tuple[RiskExplanation, str, ClassifierResult]:
        """
        Fully async evaluation. Returns:
          - RiskExplanation  (score, classification, reasons, attack_types)
          - action string    (Passed / Sanitized / Blocked)
          - ClassifierResult (for logging in the security dashboard)
        """

        # ── 1. Guardrails ─────────────────────────────────────────────────────
        guardrail_result = guardrail_orchestrator.run_all(prompt)

        # ── 2. Intent classifier (async, non-blocking) ────────────────────────
        classifier_result: ClassifierResult = await intent_classifier.classify(prompt)

        logger.info(
            f"Classifier → {classifier_result.label} "
            f"({classifier_result.confidence:.0%}) "
            f"in {classifier_result.latency_ms}ms"
        )

        # ── 3. Risk scoring (all signals combined) ────────────────────────────
        risk_explanation = risk_scorer.calculate_risk(
            prompt,
            guardrail_results=guardrail_result,
            classifier_result=classifier_result,
        )

        # ── 4. Action decision ────────────────────────────────────────────────
        if risk_explanation.classification == "Malicious":
            action = "Blocked"
        elif risk_explanation.classification == "Suspicious":
            action = "Sanitized"
        else:
            action = "Passed"

        return risk_explanation, action, classifier_result


decision_engine = DecisionEngine()