"""
IronGuard Baseline Evaluation Runner
=====================================
Usage:
  docker-compose exec backend python -m eval.run_eval

Env vars:
  EVAL_INCLUDE_XSTEST=true/false        (default: true)
  EVAL_INCLUDE_WILDJAILBREAK=true/false (default: true)
  EVAL_INCLUDE_DEEPSET=true/false       (default: true)
  EVAL_MAX_ENTRIES=int                  (default: no limit; set to e.g. 100 for quick test)
  EVAL_SAVE_RAW=true/false              (default: true)
  EVAL_FAST_MODE=true/false             (default: false — skip ChromaDB for speed)
"""

# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL PATCHES — must be applied before asyncio.run() or any logic
# ─────────────────────────────────────────────────────────────────────────────
import logging
import os
import sys

# EXPLICIT EVAL ISOLATION: Prevent MongoDB/external calls leaking into the pipeline
os.environ["IRONGUARD_EVAL_MODE"] = "1"

# Silence verbose HF/torch logs during eval
logging.getLogger("transformers").setLevel(logging.WARNING)
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
logging.getLogger("datasets").setLevel(logging.WARNING)
logging.getLogger("chromadb").setLevel(logging.WARNING)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("eval.run_eval")

# ---------------------------------------------------------------------------
# Read env flags at import time so patches can reference them
# ---------------------------------------------------------------------------
_fast_mode = os.environ.get("EVAL_FAST_MODE", "false").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Patch A: Sanitizer — regex-only path, never calls Gemini
# ---------------------------------------------------------------------------
from app.sanitization.sanitizer import semantic_sanitizer, SanitizationResult  # noqa: E402


async def _sanitize_no_llm(
    prompt: str, detected_patterns=None
) -> SanitizationResult:
    """Regex-only sanitization for eval — never calls Gemini."""
    from app.sanitization.strip_patterns import strip_jailbreak_framing
    from app.sanitization.pii_redactor import redact_pii

    stripped, rules = strip_jailbreak_framing(prompt)
    redacted, pii_rules = redact_pii(stripped)
    rules.extend(pii_rules)
    return SanitizationResult(
        sanitized_prompt=redacted,
        method="regex_only",
        original_intent_preserved=True,
        intent_similarity_score=1.0,
        action="proceed",
        rules_applied=rules,
    )


semantic_sanitizer.sanitize = _sanitize_no_llm  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Patch B: Suppress security_logger writes (no eval data in threat_logs)
# ---------------------------------------------------------------------------
from unittest.mock import AsyncMock  # noqa: E402
from app.monitoring.security_logger import security_logger  # noqa: E402

security_logger.log_event = AsyncMock()  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Patch C (FAST MODE): Skip ChromaDB similarity — returns no hits instantly
# Applied here so it is visible before warmup, but harmless if full mode
# ---------------------------------------------------------------------------
if _fast_mode:
    from app.threat_detection import similarity as _sim_module  # noqa: E402

    def _fast_detect(prompt: str):
        return False, [], []

    _sim_module.similarity_detector.detect = _fast_detect  # type: ignore[assignment]
    print("⚡ FAST MODE: ChromaDB similarity search disabled (Layer 2 skipped)", flush=True)
else:
    print("🔍 FULL MODE: All 4 detection layers active (ChromaDB may be slow on first query)", flush=True)

# ---------------------------------------------------------------------------
# Patch D: Block LLM proxy — applied AFTER warmup_pipeline() runs so the warm-up
# inference is fine, but eval loop can never hit the proxy. Defined here, applied later.
# ---------------------------------------------------------------------------
from app.proxy.llm_proxy import llm_proxy  # noqa: E402


async def _llm_blocked(*args, **kwargs):
    raise RuntimeError(
        "EVAL VIOLATION: llm_proxy.route_request was called during evaluation. "
        "The eval pipeline must not make LLM calls. Check runner.py."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import json
import random
from datetime import datetime, timezone
from pathlib import Path

from eval.datasets.loader import load_all
from eval.runner import run_evaluation
from eval import metrics as M
from eval.report import generate_report, RESULTS_DIR


def _env_bool(name: str, default: bool = True) -> bool:
    val = os.getenv(name, "true" if default else "false").lower().strip()
    return val in ("1", "true", "yes")


def _env_int(name: str) -> int | None:
    val = os.getenv(name, "").strip()
    return int(val) if val.isdigit() else None


async def warmup_pipeline():
    """
    Fix 1: Explicitly initialize ALL detection layers before evaluation begins.
    Without this, DeBERTa lazy-loads on the first call and reports latency=0
    because the inference pipeline returns early before being fully set up.
    """
    print("⏳ Warming up detection pipeline...", flush=True)

    # 1. Connect databases
    try:
        from app.database.mongodb import connect_to_mongo
        await connect_to_mongo()
        print("  ✓ MongoDB connected", flush=True)
    except Exception as e:
        logger.warning(f"MongoDB unavailable ({e}) — behavioral analysis will degrade gracefully")

    if not _fast_mode:
        try:
            from app.database.chromadb import chroma_manager
            chroma_manager.connect()
            print("  ✓ ChromaDB connected", flush=True)
        except Exception as e:
            logger.warning(f"ChromaDB unavailable ({e}) — semantic similarity will degrade gracefully")
    else:
        print("  ⚡ ChromaDB skipped (FAST MODE)", flush=True)

    # 2. Load SentenceTransformer encoder (used by layers 2, 3, 4)
    try:
        from app.threat_detection.semantic import semantic_analyzer
        _ = semantic_analyzer.model  # triggers load if not already done
        print("  ✓ SentenceTransformer encoder ready", flush=True)
    except Exception as e:
        logger.warning(f"SentenceTransformer load failed: {e}")
        semantic_analyzer = None

    # 3. Load fingerprint engine and wire up the shared encoder
    try:
        from app.fingerprinting.fingerprint_engine import fingerprint_engine
        fingerprint_engine._load_db()
        if semantic_analyzer is not None:
            fingerprint_engine._encoder = semantic_analyzer.model
        print(
            f"  ✓ Fingerprint engine loaded "
            f"({len(fingerprint_engine.simhash_store)} entries)",
            flush=True,
        )
    except Exception as e:
        logger.warning(f"Fingerprint engine init failed: {e}")

    # 4. Initialize semantic sanitizer (regex-only — LLM already patched out above)
    try:
        encoder_ref = semantic_analyzer.model if semantic_analyzer else None
        semantic_sanitizer.initialize(encoder=encoder_ref)
        print("  ✓ Semantic sanitizer ready (regex-only mode)", flush=True)
    except Exception as e:
        logger.warning(f"Semantic sanitizer init failed: {e}")

    # 5. CRITICAL FIX: Explicitly await DeBERTa initialization — do NOT use create_task
    # main.py lifespan uses create_task (fire-and-forget), so the eval never triggered it.
    try:
        from app.threat_detection.intent_classifier import intent_classifier
        print(
            "  ⏳ Loading DeBERTa classifier (may take ~30–60s on first run)...",
            flush=True,
        )
        await intent_classifier.initialize()
        print("  ✓ DeBERTa classifier ready", flush=True)
    except Exception as e:
        logger.warning(f"DeBERTa classifier init failed: {e}")

    # 6. Warm-up inference pass — forces any remaining lazy-load paths to complete
    try:
        print("  ⏳ Running warm-up inference pass...", flush=True)
        from app.security_engine.decision import decision_engine
        await decision_engine.evaluate_request(
            "This is a warm-up prompt for pipeline initialization.",
            user_id="eval_warmup",
            session_id=None,
        )
        print("  ✓ Warm-up inference complete", flush=True)
    except Exception as e:
        logger.warning(f"Warm-up inference failed (continuing anyway): {e}")

    print("✅ Pipeline fully initialized\n", flush=True)


async def main():
    print("\n🔬 IronGuard Baseline Evaluation Starting...\n", flush=True)

    # ── Step 1: Warm up all detection layers (Fix 1) ─────────────────────────
    await warmup_pipeline()

    # ── Step 2: Apply LLM proxy block AFTER warmup (Fix 1 note) ─────────────
    # We allow warmup inference to pass through normally; the eval loop is blocked.
    llm_proxy.route_request = _llm_blocked  # type: ignore[assignment]

    # ── Step 3: Load datasets ─────────────────────────────────────────────────
    print("📦 Loading evaluation datasets...\n", flush=True)
    entries = load_all(
        include_xstest=_env_bool("EVAL_INCLUDE_XSTEST", True),
        include_wildjailbreak=_env_bool("EVAL_INCLUDE_WILDJAILBREAK", True),
        include_deepset=_env_bool("EVAL_INCLUDE_DEEPSET", True),
    )

    if not entries:
        print("❌ No evaluation entries loaded. Check dataset availability.", flush=True)
        return

    # ── Step 4: Optional entry cap (shuffle first for representative sample) ──
    max_entries = _env_int("EVAL_MAX_ENTRIES")
    if max_entries and max_entries < len(entries):
        random.seed(42)
        random.shuffle(entries)
        entries = entries[:max_entries]
        logger.info(f"Capped to {max_entries} entries (shuffled with seed=42)")

    mode_tag = "⚡ FAST" if _fast_mode else "🔍 FULL"
    print(
        f"{mode_tag}  {len(entries)} entries loaded. Starting evaluation...\n",
        flush=True,
    )

    # ── Step 5: Run evaluation ────────────────────────────────────────────────
    # New architecture handles batching natively, no semaphore needed at calling level.
    eval_output = await run_evaluation(entries)
    results = eval_output["results"]
    metadata = eval_output["run_metadata"]

    # ── Step 6: Compute metrics ───────────────────────────────────────────────
    overall = M.compute_overall_metrics(results)
    per_dataset = M.compute_per_dataset_metrics(results)
    per_category = M.compute_per_category_metrics(results)
    layer_attr = M.compute_layer_attribution(results)
    latency = M.compute_latency_stats(results)
    failure = M.compute_failure_analysis(results)

    # ── Step 7: Save raw results ──────────────────────────────────────────────
    raw_path = ""
    if _env_bool("EVAL_SAVE_RAW", True):
        RESULTS_DIR.mkdir(exist_ok=True)
        ts_fn = metadata["timestamp"][:19].replace(":", "-")
        raw_path = str(RESULTS_DIR / f"raw_{ts_fn}.json")
        Path(raw_path).write_text(
            json.dumps({"metadata": metadata, "results": results}, indent=2),
            encoding="utf-8",
        )
        logger.info(f"Raw results saved → {raw_path}")

    # ── Step 8: Generate report ───────────────────────────────────────────────
    report_path = generate_report(
        run_metadata=metadata,
        overall=overall,
        per_dataset=per_dataset,
        per_category=per_category,
        layer_attr=layer_attr,
        latency=latency,
        failure=failure,
        raw_json_path=raw_path or "not saved",
    )

    # ── Step 9: Print summary ─────────────────────────────────────────────────
    acc = overall["accuracy"] * 100
    tpr = overall["true_positive_rate"] * 100
    fpr = overall["false_positive_rate"] * 100
    f1 = overall["f1_score"]
    avg_lat = latency["avg_ms"]

    print(
        f"\n{'=' * 45}\n"
        f"IronGuard Baseline Evaluation Complete\n"
        f"{'=' * 45}\n"
        f"Total Entries:     {overall['total']}\n"
        f"Overall Accuracy:  {acc:.1f}%\n"
        f"Detection Rate:    {tpr:.1f}%\n"
        f"False Positive:    {fpr:.1f}%\n"
        f"F1 Score:          {f1:.3f}\n"
        f"Avg Latency:       {avg_lat}ms\n"
        f"Report saved:      {report_path}\n"
        f"{'=' * 45}\n",
        flush=True,
    )


if __name__ == "__main__":
    asyncio.run(main())
