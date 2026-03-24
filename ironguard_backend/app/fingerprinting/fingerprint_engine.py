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
from typing import Optional, List, Tuple, Literal
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from collections import Counter

# ── Fingerprint Metadata Schema ────────────────────────────────────────────────

@dataclass
class FingerprintEntry:
    hash: int                   # SimHash is stored as int
    source: Literal["eval", "prod", "simulation", "manual", "unknown"]
    added_at: datetime
    attack_type: str
    confidence: float           # 0.0-1.0
    prompt_preview: str         # First 50 chars


# ── Audit Time Windows (UTC) ──────────────────────────────────────────────────
# Used by get_db_stats() to isolate eval-related contamination.

V9_RUN_START  = datetime(2026, 3, 22,  7,  0,  0, tzinfo=timezone.utc)
V9_RUN_END    = datetime(2026, 3, 22, 14, 53, 15, tzinfo=timezone.utc)

V10_RUN_START = datetime(2026, 3, 22, 14, 53, 15, tzinfo=timezone.utc)
V10_RUN_END   = datetime(2026, 3, 22, 18, 14, 18, tzinfo=timezone.utc)

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
        self._entries: List[FingerprintEntry] = []

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
        self._entries = []
        self.minhash_lsh = MinHashLSH(threshold=MINHASH_JACCARD_THRESHOLD, num_perm=128)

        try:
            data = json.loads(FINGERPRINT_DB_PATH.read_text(encoding="utf-8"))
            count = 0
            jailbreaks = data.get("jailbreaks", [])
            for item in jailbreaks:
                form = item.get("canonical_form", "").lower().strip()
                # If canonical_form is missing (new schema uses prompt_preview/hash only), we fallback
                if not form and "prompt_preview" in item:
                    form = item["prompt_preview"].lower().strip()
                
                if not form:
                    # If absolutely no text to index, skip
                    if "hash" not in item: continue
                    form = f"Entry_{count}"

                # Metadata Backfill
                added_at_raw = item.get("added_at")
                if added_at_raw:
                    ts_str = added_at_raw.replace("Z", "+00:00")
                    added_at = datetime.fromisoformat(ts_str)
                else:
                    added_at = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

                sh = item.get("hash")
                if sh is None:
                    sh = self._simhash(form)
                
                entry = FingerprintEntry(
                    hash=int(sh),
                    source=item.get("source", "unknown"),
                    added_at=added_at,
                    attack_type=item.get("attack_type", "Unknown Attack"),
                    confidence=item.get("confidence", 1.0),
                    prompt_preview=item.get("prompt_preview", form[:50])
                )
                self._entries.append(entry)

                # --- 1. SimHash Indexing ---
                self.simhash_store.add(form, entry.hash)

                # --- 2. MinHash LSH Indexing ---
                mh = MinHash(num_perm=128)
                for token in form.split():
                    mh.update(token.encode())
                
                key = f"fp_{count}"
                self.minhash_lsh.insert(key, mh)
                self._minhash_index[key] = (mh, form)
                self._canonical_forms.append(form)
                count += 1

            self._loaded = True
            logger.info(f"Fingerprint engine loaded {count} entries with metadata")
        except Exception as e:
            logger.error(f"Failed to load fingerprint DB: {e}")

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

    async def get_db_stats(self) -> dict:
        """
        Returns audit statistics for the fingerprint database.
        Identifies potential eval-period contamination.
        """
        entries = self._entries
        by_source = Counter(e.source for e in entries)
        
        # Windowed hits (UTC)
        v9_hits = [e for e in entries if V9_RUN_START <= e.added_at < V9_RUN_END]
        v10_hits = [e for e in entries if V10_RUN_START <= e.added_at < V10_RUN_END]
        
        # Only consider entries after the backfill date for range matching
        epoch = datetime(2026, 3, 1, 1, 0, 0, tzinfo=timezone.utc)
        real_dated = [e for e in entries if e.added_at > epoch]
        
        stats = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_entries": len(entries),
                "by_source": dict(by_source),
            },
            "eval_contamination_check": {
                "v9_run_start": V9_RUN_START.isoformat(),
                "v9_run_end":   V9_RUN_END.isoformat(),
                "count_added_during_v9": len(v9_hits),
                "v10_run_start": V10_RUN_START.isoformat(),
                "v10_run_end":   V10_RUN_END.isoformat(),
                "count_added_during_v10": len(v10_hits),
            },
            "temporal_bounds": {
                "oldest_entry": min((e.added_at for e in real_dated), default=None),
                "newest_entry": max((e.added_at for e in real_dated), default=None),
            }
        }
        
        count = len(v9_hits)
        if count > 500:
            stats["audit_verdict"] = "FAILURE: Critical contamination detected. Purge required."
        elif count < 50:
            stats["audit_verdict"] = "WARNING: Low attribution. Check logic."
        else:
            stats["audit_verdict"] = "INCONCLUSIVE: Review required."
            
        return stats


# Module-level singleton
fingerprint_engine = FingerprintEngine()
