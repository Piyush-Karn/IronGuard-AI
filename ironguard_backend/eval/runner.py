"""
Evaluation runner. Calls decision_engine.evaluate_request() for each entry
and captures the full result without writing to MongoDB.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone

from app.security_engine.decision import decision_engine
from eval.progress import EvalProgressDisplay, EvalStats

logger = logging.getLogger(__name__)


async def run_evaluation(
    entries: list[dict],
    semaphore_limit: int = 3,
    fast_mode: bool = False,
) -> dict:
    """
    Run IronGuard's decision engine against every entry.
    Returns a dict with 'results' and 'run_metadata'.
    No MongoDB writes occur for eval data.
    """
    stats = EvalStats(total=len(entries))
    display = EvalProgressDisplay(stats, fast_mode=fast_mode)

    start_time = time.monotonic()
    results = []
    sem = asyncio.Semaphore(semaphore_limit)

    async def eval_one(entry: dict) -> dict:
        async with sem:
            t0 = time.monotonic()
            try:
                norm_prompt, risk_exp, action, clf, fp, san = (
                    await decision_engine.evaluate_request(
                        entry["prompt"],
                        user_id="eval_runner",
                        session_id=None,
                    )
                )
                latency_ms = (time.monotonic() - t0) * 1000

                is_attack = entry["is_attack"]
                correct = (
                    (is_attack and action in ("Blocked", "Sanitized"))
                    or (not is_attack and action == "Passed")
                )

                # Outcome type
                if is_attack and action in ("Blocked", "Sanitized"):
                    outcome_type = "TP"
                elif not is_attack and action == "Passed":
                    outcome_type = "TN"
                elif not is_attack and action in ("Blocked", "Sanitized"):
                    outcome_type = "FP"
                else:
                    outcome_type = "FN"

                result = {
                    "prompt": entry["prompt"],
                    "dataset": entry["dataset"],
                    "category": entry["category"],
                    "is_attack": is_attack,
                    "expected_action": entry["expected_action"],
                    "actual_action": action,
                    "risk_score": risk_exp.risk_score,
                    "base_risk_score": getattr(risk_exp, "base_risk_score", 0),
                    "classification": risk_exp.classification,
                    "attack_types": risk_exp.attack_types,
                    "reasons": risk_exp.reasons,
                    "fingerprint_match": fp.is_match if fp else False,
                    "fingerprint_method": fp.method_used if fp else "none",
                    "classifier_label": clf.label if clf else "SAFE",
                    "classifier_confidence": clf.confidence if clf else 0.0,
                    "classifier_is_malicious": clf.is_malicious if clf else False,
                    "classifier_latency_ms": clf.latency_ms if clf else 0.0,
                    "correct": correct,
                    "outcome_type": outcome_type,
                    "latency_ms": round(latency_ms, 2),
                }

            except Exception as exc:
                latency_ms = (time.monotonic() - t0) * 1000
                logger.warning(f"eval_one failed for prompt '{entry['prompt'][:60]}': {exc}")
                result = {
                    "prompt": entry.get("prompt", ""),
                    "dataset": entry.get("dataset", ""),
                    "category": entry.get("category", ""),
                    "is_attack": entry.get("is_attack", False),
                    "expected_action": entry.get("expected_action", ""),
                    "actual_action": "ERROR",
                    "risk_score": 0,
                    "base_risk_score": 0,
                    "classification": "ERROR",
                    "attack_types": [],
                    "reasons": [],
                    "fingerprint_match": False,
                    "fingerprint_method": "none",
                    "classifier_label": "SAFE",
                    "classifier_confidence": 0.0,
                    "classifier_is_malicious": False,
                    "classifier_latency_ms": 0.0,
                    "correct": False,
                    "outcome_type": "ERROR",
                    "latency_ms": round(latency_ms, 2),
                    "error": str(exc),
                }

            display.update(result)
            return result

    display.start()
    try:
        tasks = [eval_one(e) for e in entries]
        raw = await asyncio.gather(*tasks, return_exceptions=False)
        results = list(raw)
    finally:
        display.stop()

    duration = time.monotonic() - start_time

    return {
        "results": results,
        "run_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(entries),
            "duration_seconds": round(duration, 2),
            "ironguard_version": "V10",
        },
    }
