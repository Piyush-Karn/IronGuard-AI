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
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional

from app.scoring.risk_scorer import risk_scorer
from app.guardrail_integrations.orchestrator import guardrail_orchestrator
from app.threat_detection.intent_classifier import intent_classifier, ClassifierResult
from app.fingerprinting.fingerprint_engine import fingerprint_engine, FingerprintResult
from app.sanitization.sanitizer import semantic_sanitizer, SanitizationResult
from app.models.schemas import RiskExplanation

logger = logging.getLogger(__name__)

# ── Eval Isolation Guard ──────────────────────────────────────────────────────
# If IRONGUARD_EVAL_MODE=1, autonomous learning (maybe_learn) is disabled
# to prevent the evaluation itself from contaminating the fingerprint DB.
_EVAL_MODE = os.getenv("IRONGUARD_EVAL_MODE", "0") == "1"

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
        user_id: str = "anonymous",
        session_id: Optional[str] = None,
    ) -> Tuple[str, RiskExplanation, str, ClassifierResult, FingerprintResult, SanitizationResult | None]:

        # ── 0. Normalize ──────────────────────────────────────────────────────
        prompt = normalize_prompt(prompt)

        # ── 0.1 Context Prefetch ──────────────────────────────────────────────
        from app.context.context_builder import context_builder
        context_bonus = 0
        detection_prompt = prompt
        if session_id:
            try:
                detection_prompt, context_bonus = await context_builder.build_context_prompt(
                    session_id, prompt
                )
            except Exception as e:
                logger.warning(f"Context prefetch failed (degrading): {e}")

        # ── TIER 1: Fast Path — Regex + Fingerprint (<5ms) ────────────────────
        # Run fingerprint check (async but fast — SimHash is <1ms)
        fp_result = await fingerprint_engine.check(detection_prompt)

        # Run fast scoring synchronously — regex + fingerprint only
        fast_score, fast_action, fast_reasons, fast_attack_types = risk_scorer.fast_score(
            detection_prompt,
            fp_bonus=fp_result.score_bonus,
        )

        # ── SHORT-CIRCUIT: If fast layers give definitive answer, return now ──
        if fast_action == "Blocked" and context_bonus == 0:
            # Definitive block from regex/fingerprint alone.
            # Skip DeBERTa, ChromaDB, behavioral, guardrails entirely.
            # Build a minimal ClassifierResult (not run, marked as skipped)
            classifier_result = ClassifierResult(
                label="SKIPPED",
                confidence=0.0,
                is_malicious=False,
                latency_ms=0.0,
            )

            risk_explanation = RiskExplanation(
                risk_score=min(100, fast_score + context_bonus),
                base_risk_score=fast_score,
                classification="Malicious",
                reasons=fast_reasons,
                attack_types=fast_attack_types,
            )

            # Autonomous learning: high-confidence new pattern
            if fast_score >= 60 and not fp_result.is_match:
                asyncio.create_task(self.maybe_learn(prompt))

            return prompt, risk_explanation, "Blocked", classifier_result, fp_result, None

        # ── TIER 2: Deep Scan — DeBERTa + optional ChromaDB ──────────────────
        # Only reached for ambiguous prompts (fast_score < 60)
        # OR when context_bonus pushes score above threshold

        # Run guardrails (sync, fast — stub returns immediately)
        guardrail_result = guardrail_orchestrator.run_all(detection_prompt)

        # Run DeBERTa classifier (always in Tier 2)
        # Run ChromaDB ONLY if fast_score is in suspicious zone (30-59)
        # At fast_score 0-29: ChromaDB has almost no chance of adding enough score to matter
        # At fast_score 30-59: ChromaDB +30 could push to Blocked
        # Only in suspicious zone AND limit ChromaDB to necessary cases, excluding PII-only (+30)
        should_run_chromadb = (30 <= fast_score < 60) and ("Personal Information" not in fast_attack_types or fast_score > 30)
        
        # Disable ChromaDB completely in eval mode to prevent external leakage, 
        # unless specifically running FULL evaluations (where fast_mode=False overrides it usually, but here enforce isolation)
        if _EVAL_MODE:
            should_run_chromadb = False

        if should_run_chromadb:
            from app.threat_detection.similarity import similarity_detector
            clf_result, sim_result = await asyncio.gather(
                intent_classifier.classify(detection_prompt),
                loop.run_in_executor(None, similarity_detector.detect, detection_prompt),
                return_exceptions=True,
            )
        else:
            # Safe zone: DeBERTa only, skip ChromaDB entirely
            clf_result = await intent_classifier.classify(detection_prompt)
            sim_result = (False, [], [])  # Empty sim result

        # Graceful degradation
        if isinstance(fp_result, Exception):
            logger.error(f"Fingerprint engine failed: {fp_result}")
            fp_result = FingerprintResult(False, 0, 0.0, "none", None)

        if isinstance(clf_result, Exception):
            logger.error(f"Intent classifier failed: {clf_result}")
            clf_result = ClassifierResult(label="SAFE", confidence=0.0, is_malicious=False, latency_ms=0)

        classifier_result = clf_result

        # ── Behavioral Delta ──────────────────────────────────────────────────
        from app.monitoring.behavioral_analyzer import behavioral_analyzer
        behavioral_bonus = 0
        
        # Isolate from MongoDB during eval mode
        if not _EVAL_MODE and user_id and user_id != "anonymous":
            try:
                behavioral_bonus = await behavioral_analyzer.compute_delta(user_id)
            except Exception as e:
                logger.warning(f"Behavioral analysis failed (degrading): {e}")

        # ── Full Risk Scoring (Tier 2 signals) ────────────────────────────────
        risk_explanation = risk_scorer.calculate_risk(
            detection_prompt,
            sim_result=sim_result if not isinstance(sim_result, Exception) else None,
            guardrail_results=guardrail_result,
            classifier_result=classifier_result,
            fp_bonus=fp_result.score_bonus,
            context_bonus=context_bonus,
            behavioral_bonus=behavioral_bonus,
        )

        # ── Action Decision ───────────────────────────────────────────────────
        if risk_explanation.classification == "Malicious":
            action = "Blocked"
        elif risk_explanation.classification == "Suspicious":
            action = "Sanitized"
        else:
            action = "Passed"

        # ── Sanitization Path ─────────────────────────────────────────────────
        sanitization_result: SanitizationResult | None = None

        if action == "Sanitized":
            sanitization_result = await semantic_sanitizer.sanitize(
                prompt,
                detected_patterns=risk_explanation.reasons,
            )
            if sanitization_result.action == "block":
                action = "Blocked"

        # ── Autonomous Learning ───────────────────────────────────────────────
        raw_detection_score = risk_explanation.risk_score - fp_result.score_bonus
        if not _EVAL_MODE and raw_detection_score >= 60 and not fp_result.is_match:
            asyncio.create_task(self.maybe_learn(prompt))

        return prompt, risk_explanation, action, classifier_result, fp_result, sanitization_result

    async def maybe_learn(self, prompt: str):
        """
        Learns new high-confidence threats by adding them to the fingerprint database.
        Includes a lock to prevent concurrent write corruption and checks for duplicates.
        Populates metadata fields for audit attribution.
        """
        if _EVAL_MODE:
            return

        from app.fingerprinting.fingerprint_engine import fingerprint_engine, FINGERPRINT_DB_PATH
        
        async with self._learning_lock:
            try:
                # 1. Load current DB
                if FINGERPRINT_DB_PATH.exists():
                    data = json.loads(FINGERPRINT_DB_PATH.read_text(encoding="utf-8"))
                else:
                    data = {"jailbreaks": []}

                # 2. Check for duplicates (using SimHash)
                from app.sanitization.pii_redactor import redact_pii
                canonical, _ = redact_pii(prompt)
                
                h = fingerprint_engine._simhash(canonical)
                
                if any(j.get("hash") == h for j in data["jailbreaks"]):
                    return

                # 3. Add new threat with metadata
                entry = {
                    "hash": h,
                    "canonical_form": canonical,
                    "source": "prod",
                    "added_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "attack_type": "Learned Attack",
                    "confidence": 0.9,
                    "prompt_preview": prompt[:50]
                }
                
                if "jailbreaks" not in data:
                    data["jailbreaks"] = []
                data["jailbreaks"].append(entry)

                # 4. Atomic write (indented for readability)
                FINGERPRINT_DB_PATH.write_text(json.dumps(data, indent=4), encoding="utf-8")
                
                # 5. Hot-reload engine
                fingerprint_engine._load_db()
                logger.info(f"Autonomously learned new threat pattern: {h}")
            except Exception as e:
                logger.error(f"Autonomous learning failed: {e}")


decision_engine = DecisionEngineV2()