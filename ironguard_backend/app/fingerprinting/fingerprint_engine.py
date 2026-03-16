"""
MOD-3: Fingerprint Engine
=========================
Three-signal cascade for detecting mutated/paraphrased jailbreak prompts:
  1. SimHash (Hamming distance on 128-bit hashes)     ~0.1ms
  2. MinHash LSH (Jaccard similarity on token n-grams) ~1ms
  3. Cosine similarity (embedding-based)               ~4ms — only if 1&2 miss

All three run on the same call. A hit on ANY method triggers the score bonus.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from datasketch import MinHash, MinHashLSH

from app.fingerprinting.simhash_store import SimHashStore

logger = logging.getLogger(__name__)

FINGERPRINT_DB_PATH = Path(__file__).parent / "fingerprint_db.json"

# Tunable thresholds
SIMHASH_BIT_THRESHOLD = 10    # Hamming distance ≤ 10 of 128 bits (7.8% mutation tolerance)
MINHASH_JACCARD_THRESHOLD = 0.55  # Slightly relaxed from 0.65 for better recall
COSINE_THRESHOLD = 0.88
SCORE_BONUS = 25


class FingerprintResult:
    def __init__(
        self,
        is_match: bool,
        score_bonus: int,
        similarity_score: float,
        method_used: str,
        matched_canonical: Optional[str],
    ):
        self.is_match = is_match
        self.score_bonus = score_bonus
        self.similarity_score = similarity_score
        self.method_used = method_used
        self.matched_canonical = matched_canonical

    def to_dict(self) -> dict:
        return {
            "is_match": self.is_match,
            "score_bonus": self.score_bonus,
            "similarity_score": self.similarity_score,
            "method_used": self.method_used,
            "matched_canonical": self.matched_canonical,
        }


class FingerprintEngine:
    """
    Multi-signal fingerprint detector for known jailbreak prompt mutations.
    The fingerprint store is hot-reloadable by calling _load_db() at runtime.
    """

    def __init__(self):
        self.simhash_store = SimHashStore()
        self.minhash_lsh: Optional[MinHashLSH] = None
        self._minhash_index: dict[str, MinHash] = {}   # for exact Jaccard scoring
        self._canonical_forms: list[str] = []
        self._canonical_embeddings: list = []
        self._encoder = None   # set via initialize() to avoid circular import
        self._loaded = False

    def _simhash(self, text: str) -> int:
        """
        128-bit SimHash of character 3-grams.
        Uses fast Knuth multiplicative hash instead of MD5 (~20x faster for short grams).
        """
        bits = [0] * 128
        for i in range(len(text) - 2):
            gram = text[i : i + 3]
            # Fast 64-bit multiplicative hash — no crypto overhead
            h = int.from_bytes(gram.encode("utf-8", errors="replace"), "little") * 2654435761
            h &= 0xFFFFFFFFFFFFFFFF
            # Expand to 128 bits
            h2 = (h ^ (h >> 33)) * 0xFF51AFD7ED558CCD & 0xFFFFFFFFFFFFFFFF
            combined = (h << 64) | h2
            for j in range(128):
                bits[j] += 1 if (combined >> j) & 1 else -1
        return sum(1 << j for j, b in enumerate(bits) if b > 0)

    def _load_db(self):
        """Load fingerprint DB from JSON. Safe to call at runtime for hot-reload."""
        if not FINGERPRINT_DB_PATH.exists():
            logger.warning("Fingerprint DB not found — skipping fingerprint detection")
            return

        # Reset stores
        self.simhash_store.clear()
        self._minhash_index.clear()
        self._canonical_forms.clear()
        self.minhash_lsh = MinHashLSH(threshold=MINHASH_JACCARD_THRESHOLD, num_perm=128)

        data = json.loads(FINGERPRINT_DB_PATH.read_text(encoding="utf-8"))
        count = 0
        for item in data.get("jailbreaks", []):
            form = item.get("canonical_form", "").lower().strip()
            if not form:
                continue

            # --- SimHash ---
            sh = self._simhash(form)
            self.simhash_store.add(form, sh)

            # --- MinHash ---
            mh = MinHash(num_perm=128)
            for token in form.split():
                mh.update(token.encode())
            # MinHashLSH.insert requires unique keys
            key = f"fp_{count}"
            self.minhash_lsh.insert(key, mh)
            self._minhash_index[key] = (mh, form)
            self._canonical_forms.append(form)
            count += 1

        self._loaded = True
        logger.info(f"Fingerprint engine loaded {count} canonical forms")

    def set_encoder(self, encoder):
        """Attach a pre-loaded SentenceTransformer encoder for cosine similarity."""
        self._encoder = encoder
        # Pre-compute embeddings for all canonical forms
        if encoder and self._canonical_forms:
            try:
                self._canonical_embeddings = encoder.encode(
                    self._canonical_forms, show_progress_bar=False
                )
                logger.info(f"Pre-computed {len(self._canonical_embeddings)} canonical embeddings")
            except Exception as e:
                logger.warning(f"Could not pre-compute canonical embeddings: {e}")

    async def check(self, prompt: str, embedding=None) -> FingerprintResult:
        """
        Run three-signal fingerprint check. Gracefully degrades if not loaded.
        """
        if not self._loaded:
            return FingerprintResult(False, 0, 0.0, "none", None)

        loop = asyncio.get_event_loop()
        # Run CPU-bound SimHash + MinHash in executor to not block asyncio
        result = await loop.run_in_executor(None, self._check_sync, prompt, embedding)
        return result

    def _check_sync(self, prompt: str, embedding=None) -> FingerprintResult:
        text = prompt.lower().strip()
        best_score = 0.0
        matched_canonical = None
        method_used = "none"

        # ── Signal 1: SimHash ────────────────────────────────────────────────
        ph = self._simhash(text)
        sh_distance, sh_canonical = self.simhash_store.query(ph, SIMHASH_BIT_THRESHOLD)
        simhash_match = sh_distance is not None
        if simhash_match:
            sh_score = 1.0 - (sh_distance / 128.0)
            if sh_score > best_score:
                best_score = sh_score
                matched_canonical = sh_canonical
                method_used = "simhash"

        # ── Signal 2: MinHash (Jaccard) ───────────────────────────────────────
        mh = MinHash(num_perm=128)
        for token in text.split():
            mh.update(token.encode())

        minhash_keys = self.minhash_lsh.query(mh)
        minhash_match = len(minhash_keys) > 0
        if minhash_match:
            # Find best Jaccard among all matches
            for key in minhash_keys:
                ref_mh, canonical_form = self._minhash_index.get(key, (None, None))
                if ref_mh is not None:
                    jaccard = mh.jaccard(ref_mh)
                    if jaccard > best_score:
                        best_score = jaccard
                        matched_canonical = canonical_form
                        method_used = "minhash"

        # ── Signal 3: Cosine (only if 1 & 2 both miss) ───────────────────────
        cosine_match = False
        if not simhash_match and not minhash_match and self._encoder is not None and len(self._canonical_embeddings) > 0:
            try:
                from sentence_transformers import util as st_util
                import numpy as np
                if embedding is None:
                    embedding = self._encoder.encode(prompt, show_progress_bar=False)
                sims = st_util.cos_sim(embedding, self._canonical_embeddings)[0]
                best_idx = int(sims.argmax())
                best_sim = float(sims[best_idx])
                if best_sim >= COSINE_THRESHOLD:
                    cosine_match = True
                    if best_sim > best_score:
                        best_score = best_sim
                        matched_canonical = self._canonical_forms[best_idx]
                        method_used = "cosine"
            except Exception as e:
                logger.warning(f"Cosine fingerprint check failed: {e}")

        is_match = simhash_match or minhash_match or cosine_match
        return FingerprintResult(
            is_match=is_match,
            score_bonus=SCORE_BONUS if is_match else 0,
            similarity_score=round(best_score, 4),
            method_used=method_used,
            matched_canonical=matched_canonical,
        )


# Module-level singleton
fingerprint_engine = FingerprintEngine()
