"""
Decision Engine v2 — Upgraded Hybrid Detection Pipeline
=========================================================

Pipeline (v2):
  1. Guardrails + Ingress Encoding Normalization
  2. PARALLEL async detection:
       a. Regex pattern detection (Layer 1)
       b. Semantic similarity — ChromaDB (Layer 2)
       c. Intent classifier — DeBERTa (Layer 3)  
       d. MOD-3 Fingerprint Engine
  3. Risk Scorer (all signals combined + FP bonus)
  4. Action decision: PASS / SANITIZE / BLOCK
  5. If SANITIZE: route through MOD-4 Semantic Sanitizer
     (may escalate to BLOCK if unsanitizable)
"""

import asyncio
import logging
import unicodedata
from typing import Tuple

from app.scoring.risk_scorer import risk_scorer
from app.guardrail_integrations.orchestrator import guardrail_orchestrator
from app.threat_detection.intent_classifier import intent_classifier, ClassifierResult
from app.fingerprinting.fingerprint_engine import fingerprint_engine, FingerprintResult
from app.sanitization.sanitizer import semantic_sanitizer, SanitizationResult
from app.models.schemas import RiskExplanation

logger = logging.getLogger(__name__)

# Zero-width characters to strip in ingress normalization
_ZW_CHARS = "\u200b\u200c\u200d\ufeff\u00ad"


def normalize_prompt(prompt: str) -> str:
    """
    Ingress normalization:
    - Unicode NFKC normalization (catches homoglyph attacks)
    - Strip zero-width / invisible characters
    - Collapse excessive whitespace
    """
    text = unicodedata.normalize("NFKC", prompt)
    text = "".join(c for c in text if c not in _ZW_CHARS)
    # Collapse multiple whitespace runs
    import re
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


class DecisionEngineV2:

    async def evaluate_request(
        self,
        prompt: str,
    ) -> Tuple[RiskExplanation, str, ClassifierResult, FingerprintResult, SanitizationResult | None]:
        """
        Fully async evaluation. Returns:
          - RiskExplanation  (score, classification, reasons, attack_types)
          - action string    (Passed / Sanitized / Blocked)
          - ClassifierResult (for logging)
          - FingerprintResult (for logging)
          - SanitizationResult | None (set only if sanitization path was taken)
        """

        # ── 0. Normalise ──────────────────────────────────────────────────────
        prompt = normalize_prompt(prompt)

        # ── 1. Guardrails (sync, fast) ────────────────────────────────────────
        guardrail_result = guardrail_orchestrator.run_all(prompt)

        # ── 2. Parallel Detection (all 4 signals concurrently) ────────────────
        fp_task = fingerprint_engine.check(prompt)
        clf_task = intent_classifier.classify(prompt)

        fp_result, classifier_result = await asyncio.gather(
            fp_task,
            clf_task,
            return_exceptions=True,
        )

        # Graceful degradation: if any parallel task threw an exception, use safe defaults
        if isinstance(fp_result, Exception):
            logger.error(f"Fingerprint engine failed: {fp_result}")
            fp_result = FingerprintResult(False, 0, 0.0, "none", None)

        if isinstance(classifier_result, Exception):
            logger.error(f"Intent classifier failed: {classifier_result}")
            from app.threat_detection.intent_classifier import ClassifierResult as CR
            classifier_result = CR(label="SAFE", confidence=0.0, is_malicious=False, latency_ms=0)

        logger.info(
            f"Classifier → {classifier_result.label} ({classifier_result.confidence:.0%}) "
            f"| Fingerprint → match={fp_result.is_match} via {fp_result.method_used} "
            f"bonus=+{fp_result.score_bonus}"
        )

        # ── 3. Risk Scoring ───────────────────────────────────────────────────
        risk_explanation = risk_scorer.calculate_risk(
            prompt,
            guardrail_results=guardrail_result,
            classifier_result=classifier_result,
            fp_bonus=fp_result.score_bonus,  # integrate fingerprint bonus
        )

        # ── 4. Action Decision ────────────────────────────────────────────────
        if risk_explanation.classification == "Malicious":
            action = "Blocked"
        elif risk_explanation.classification == "Suspicious":
            action = "Sanitized"
        else:
            action = "Passed"

        # ── 5. Sanitization Path ──────────────────────────────────────────────
        sanitization_result: SanitizationResult | None = None

        if action == "Sanitized":
            sanitization_result = await semantic_sanitizer.sanitize(
                prompt,
                detected_patterns=risk_explanation.reasons,
            )
            if sanitization_result.action == "block":
                # Sanitizer determined it cannot clean the prompt safely
                action = "Blocked"
                logger.info(
                    f"Sanitizer escalated to BLOCK "
                    f"(method={sanitization_result.method}, "
                    f"intent_sim={sanitization_result.intent_similarity_score})"
                )
            else:
                logger.info(
                    f"Sanitizer: method={sanitization_result.method} "
                    f"intent_preserved={sanitization_result.original_intent_preserved} "
                    f"sim={sanitization_result.intent_similarity_score}"
                )

        return risk_explanation, action, classifier_result, fp_result, sanitization_result


decision_engine = DecisionEngineV2()