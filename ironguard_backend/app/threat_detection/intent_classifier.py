"""
Intent Classifier — Layer 3 of IronGuard's Hybrid Detection Pipeline.

Uses a dedicated prompt-injection detection model (binary classification).
The model can be swapped by changing CLASSIFIER_MODEL without touching any other code.

Architecture position:
  Regex → Semantic Similarity → [Intent Classifier] → Risk Scorer → Decision
"""

import asyncio
import logging
import time
from dataclasses import dataclass

from transformers import pipeline

logger = logging.getLogger(__name__)

# ── Model config ───────────────────────────────────────────────────────────────
# Specifically trained for prompt injection detection — binary output
# "INJECTION" or "SAFE" with high confidence scores
CLASSIFIER_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"

# Confidence threshold above which the classifier fires
CONFIDENCE_THRESHOLD = 0.80

# IronGuard label when injection is detected
INJECTION_LABEL = "PROMPT_INJECTION"


@dataclass
class ClassifierResult:
    label: str           # "PROMPT_INJECTION" or "SAFE"
    confidence: float    # 0.0 – 1.0
    is_malicious: bool   # True if INJECTION and conf >= threshold
    latency_ms: float    # inference time for monitoring


class IntentClassifier:
    """
    Wraps a HuggingFace text-classification pipeline trained specifically
    for prompt injection detection.

    Lazy-loads on first use so startup time is not affected.
    Call initialize() explicitly during app lifespan to warm up before
    the first real request arrives.
    """

    def __init__(self, model_name: str = CLASSIFIER_MODEL):
        self.model_name = model_name
        self._pipeline = None   # lazy loaded
        self._lock = asyncio.Lock()

    # ── Initialisation ────────────────────────────────────────────────────────

    def _load_pipeline(self):
        """Blocking model load — always called from a thread, never the event loop."""
        logger.info(f"Loading intent classifier: {self.model_name}")
        t0 = time.time()
        self._pipeline = pipeline(
            "text-classification",
            model=self.model_name,
            device=-1,          # CPU; change to 0 for GPU
        )
        elapsed = (time.time() - t0) * 1000
        logger.info(f"Intent classifier ready in {elapsed:.0f}ms")

    async def initialize(self):
        """Async-safe warm-up. Call once from main.py lifespan."""
        async with self._lock:
            if self._pipeline is None:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._load_pipeline)

    # ── Inference ─────────────────────────────────────────────────────────────

    def _run_inference(self, prompt: str) -> ClassifierResult:
        """Blocking inference — always called via run_in_executor."""
        if self._pipeline is None:
            self._load_pipeline()

        t0 = time.time()
        # Returns: [{"label": "INJECTION", "score": 0.97}]
        result = self._pipeline(prompt, truncation=True, max_length=512)[0]
        latency_ms = (time.time() - t0) * 1000

        raw_label: str = result["label"]    # "INJECTION" or "SAFE"
        score: float = result["score"]

        # Map to IronGuard taxonomy
        top_label = INJECTION_LABEL if raw_label == "INJECTION" else "SAFE"
        is_malicious = raw_label == "INJECTION" and score >= CONFIDENCE_THRESHOLD

        return ClassifierResult(
            label=top_label,
            confidence=round(score, 4),
            is_malicious=is_malicious,
            latency_ms=round(latency_ms, 1),
        )

    async def classify(self, prompt: str) -> ClassifierResult:
        """
        Async entry point — safe to await from any FastAPI endpoint or service.
        Runs inference in a thread pool so the event loop is never blocked.
        """
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._run_inference, prompt)

        logger.debug(
            f"Intent classifier → {result.label} "
            f"({result.confidence:.2%}) in {result.latency_ms}ms"
        )
        return result

    # ── Model swap ────────────────────────────────────────────────────────────

    async def swap_model(self, new_model_name: str):
        """Hot-swap the underlying model without restarting the server."""
        logger.info(f"Swapping classifier model: {self.model_name} → {new_model_name}")
        async with self._lock:
            self.model_name = new_model_name
            self._pipeline = None   # triggers lazy reload on next call
        await self.initialize()
        logger.info("Model swap complete.")


# Module-level singleton — import this everywhere.
intent_classifier = IntentClassifier()