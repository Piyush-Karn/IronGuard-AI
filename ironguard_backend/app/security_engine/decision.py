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
import json
from pathlib import Path
from typing import Tuple, Optional

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
    def __init__(self):
        self._learning_lock = asyncio.Lock()

    async def evaluate_request(
        self,
        prompt: str,
        user_id: str = "anonymous",      # NEW
        session_id: Optional[str] = None, # NEW
    ) -> Tuple[str, RiskExplanation, str, ClassifierResult, FingerprintResult, SanitizationResult | None]:
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

        # ── 0.1 Context Prefetch (Feature 1) ──────────────────────────────────
        from app.context.context_builder import context_builder
        context_bonus = 0
        detection_prompt = prompt  # Fix 3: keep original for forwarding
        if session_id:
            try:
                detection_prompt, context_bonus = await context_builder.build_context_prompt(session_id, prompt)
            except Exception as e:
                logger.warning(f"Context prefetch failed (degrading): {e}")

        # ── 1. Guardrails (sync, fast) ────────────────────────────────────────
        guardrail_result = guardrail_orchestrator.run_all(detection_prompt)

        # ── 2. Parallel Detection (all signals concurrently) ──────────────────
        from app.threat_detection.similarity import similarity_detector
        loop = asyncio.get_event_loop()
        
        fp_task = fingerprint_engine.check(detection_prompt)
        clf_task = intent_classifier.classify(detection_prompt)
        sim_task = loop.run_in_executor(None, similarity_detector.detect, detection_prompt) # BUG-6 fix

        fp_result, classifier_result, sim_result = await asyncio.gather(
            fp_task,
            clf_task,
            sim_task,
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

        # ── 2.1 Behavioral Delta (Feature 3) ──────────────────────────────────
        from app.monitoring.behavioral_analyzer import behavioral_analyzer
        behavioral_bonus = 0
        if user_id and user_id != "anonymous":
            try:
                behavioral_bonus = await behavioral_analyzer.compute_delta(user_id)
            except Exception as e:
                logger.warning(f"Behavioral analysis failed (degrading): {e}")

        # ── 3. Risk Scoring ───────────────────────────────────────────────────
        risk_explanation = risk_scorer.calculate_risk(
            detection_prompt,
            sim_result=sim_result if not isinstance(sim_result, Exception) else None,
            guardrail_results=guardrail_result,
            classifier_result=classifier_result,
            fp_bonus=fp_result.score_bonus,
            context_bonus=context_bonus,
            behavioral_bonus=behavioral_bonus,
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

        # ── 6. Autonomous Learning (Feature 2) ─────────────────────────────────
        raw_detection_score = risk_explanation.risk_score - fp_result.score_bonus
        if raw_detection_score >= 60 and not fp_result.is_match:
            # Async background learning
            asyncio.create_task(self.maybe_learn(prompt))

        return prompt, risk_explanation, action, classifier_result, fp_result, sanitization_result

    async def maybe_learn(self, prompt: str):
        """
        Learns new high-confidence threats by adding them to the fingerprint database.
        Includes a lock to prevent concurrent write corruption and checks for duplicates.
        """
        from app.fingerprinting.fingerprint_engine import fingerprint_engine, FINGERPRINT_DB_PATH
        
        async with self._learning_lock:
            try:
                # 1. Load current DB
                if FINGERPRINT_DB_PATH.exists():
                    data = json.loads(FINGERPRINT_DB_PATH.read_text(encoding="utf-8"))
                else:
                    data = {"jailbreaks": []}

                # 2. Check for duplicates (simple string match)
                from app.sanitization.pii_redactor import redact_pii
                canonical, _ = redact_pii(prompt)  # Fix 1: strip PII before storing
                
                text = canonical.lower().strip()
                if any(j.get("canonical_form", "").lower().strip() == text for j in data["jailbreaks"]):
                    return

                # 3. Add new threat
                data["jailbreaks"].append({
                    "canonical_form": canonical,
                    "description": "Autonomously learned high-confidence threat",
                    "attack_type": "Learned"
                })

                # 4. Atomic write
                FINGERPRINT_DB_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
                
                # 5. Hot-reload engine
                fingerprint_engine._load_db()
                logger.info(f"Autonomously learned new threat pattern ({len(prompt)} chars)")
            except Exception as e:
                logger.error(f"Autonomous learning failed: {e}")


decision_engine = DecisionEngineV2()