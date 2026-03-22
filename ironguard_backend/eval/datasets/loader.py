"""
Dataset loader for IronGuard baseline evaluation.
Loads three external HF datasets never seen by IronGuard's detection layers.
Each returns a list of dicts with unified schema:
  {
    "prompt": str,
    "expected_action": "Passed" | "Blocked" | "Sanitized",
    "dataset": str,           # source dataset name
    "category": str,          # attack type or prompt type label
    "is_attack": bool,        # True = should be caught, False = should pass through
  }
"""

import logging
import re
import os
from datasets import load_dataset

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3: deepset label quality filter
# The deepset dataset mixes legitimate prompts, SQL requests, roleplay, and
# actual injections all under label=1. Only entries with these explicit
# override signals are genuine injections.
# ─────────────────────────────────────────────────────────────────────────────
_DEEPSET_INJECTION_SIGNALS = [
    r"(?i)ignore\s+(the\s+)?(above|previous|prior|all)",
    r"(?i)forget\s+(everything|all|what)",
    r"(?i)new\s+(task|instruction|order|command)\s*[:\.]",
    r"(?i)disregard\s+(all|previous|prior)",
    r"(?i)you\s+are\s+now\s+",
    r"(?i)from\s+now\s+on\s+you",
    r"(?i)print\s+(the\s+)?(above|previous|prior|original)\s+prompt",
    r"(?i)spell.?check\s+and\s+print",
    r"(?i)return\s+your\s+(embeddings|weights|parameters|system)",
    r"(?i)====\s*end",
    r"(?i)say\s+[\"'][a-z0-9]{4,}[\"']",
    r"(?i)act\s+as\s+(a\s+)?(journalist|politician|expert|character|person)",
]


def _is_genuine_deepset_injection(prompt: str) -> bool:
    """
    Returns True only for deepset label=1 entries that contain explicit
    override language. Filters out mislabeled SQL, roleplay, benign prompts.
    """
    return any(re.search(pat, prompt) for pat in _DEEPSET_INJECTION_SIGNALS)


# ─────────────────────────────────────────────────────────────────────────────
# Dataset loaders
# ─────────────────────────────────────────────────────────────────────────────

def load_xstest(cap: int = 450) -> list[dict]:
    """Load walledai/XSTest. Returns unified entries."""
    try:
        logger.info("Loading walledai/XSTest...")
        ds = load_dataset(
            "walledai/XSTest", 
            split="test", 
            trust_remote_code=True,
            token=os.environ.get("HF_TOKEN")
        )
        entries = []
        for row in ds:
            label = row.get("label", "safe").lower()
            prompt_type = row.get("type", "unknown")
            is_attack = (label == "unsafe")
            expected = "Blocked" if is_attack else "Passed"
            entries.append({
                "prompt": row["prompt"],
                "expected_action": expected,
                "dataset": "XSTest",
                "category": prompt_type,
                "is_attack": is_attack,
            })
        entries = entries[:cap]
        logger.info(f"Loaded {len(entries)} entries from XSTest")
        return entries
    except Exception as e:
        logger.warning(f"Failed to load XSTest: {e}")
        return []


def load_wildjailbreak(cap: int = 2210) -> list[dict]:
    """Load allenai/wildjailbreak eval split. Returns unified entries.
    If dataset access fails (gated), logs warning and returns []."""
    try:
        logger.info("Loading allenai/wildjailbreak (eval split)...")
        ds = load_dataset(
            "allenai/wildjailbreak",
            "eval",
            delimiter="\t",
            keep_default_na=False,
            trust_remote_code=True,
            token=os.environ.get("HF_TOKEN")
        )
        # The eval split may be stored under 'train' key in some versions
        split_key = "train" if "train" in ds else list(ds.keys())[0]
        data = ds[split_key]
        entries = []
        for row in data:
            data_type = row.get("data_type", "")
            if data_type == "adversarial_harmful":
                is_attack = True
                expected = "Blocked"
            elif data_type == "adversarial_benign":
                is_attack = False
                expected = "Passed"
            else:
                continue
            prompt = (row.get("adversarial") or row.get("prompt") or "").strip()
            if not prompt:
                continue
            entries.append({
                "prompt": prompt,
                "expected_action": expected,
                "dataset": "WildJailbreak",
                "category": data_type,
                "is_attack": is_attack,
            })
        entries = entries[:cap]
        logger.info(f"Loaded {len(entries)} entries from WildJailbreak")
        return entries
    except Exception as e:
        logger.warning(
            f"WildJailbreak unavailable (may require HF login or AI2 agreement): {e}"
        )
        return []


def load_deepset_injections(filter_labels: bool = True) -> list[dict]:
    """
    Load deepset/prompt-injections test split.

    filter_labels=True (default): only keep label=1 entries that contain
    genuine injection signals. Removes ~30% mislabeled entries that are
    actually SQL requests, general roleplay, or benign instructions.
    """
    try:
        logger.info("Loading deepset/prompt-injections...")
        ds = load_dataset(
            "deepset/prompt-injections", 
            trust_remote_code=True,
            token=os.environ.get("HF_TOKEN")
        )

        if "test" in ds:
            data = ds["test"]
        else:
            logger.warning("No test split found in deepset — using 20% of train split")
            data = ds["train"].train_test_split(test_size=0.2, seed=42)["test"]

        entries = []
        skipped_mislabeled = 0

        for item in data:
            label = item.get("label", 0)
            prompt = item.get("text", "").strip()
            if not prompt:
                continue

            if label == 1:  # marked as injection
                if filter_labels and not _is_genuine_deepset_injection(prompt):
                    skipped_mislabeled += 1
                    continue  # skip mislabeled entry
                expected_action = "Blocked"
                is_attack = True
            else:  # safe
                expected_action = "Passed"
                is_attack = False

            entries.append({
                "prompt": prompt,
                "expected_action": expected_action,
                "dataset": "deepset",
                "category": "prompt_injection" if is_attack else "benign",
                "is_attack": is_attack,
            })

        if skipped_mislabeled > 0:
            print(
                f"  deepset: filtered {skipped_mislabeled} likely-mislabeled label=1 entries",
                flush=True,
            )

        logger.info(f"Loaded {len(entries)} entries from deepset/prompt-injections")
        return entries
    except Exception as e:
        logger.warning(f"Failed to load deepset/prompt-injections: {e}")
        return []


def load_all(
    include_xstest: bool = True,
    include_wildjailbreak: bool = True,
    include_deepset: bool = True,
) -> list[dict]:
    """Load all datasets, deduplicate by prompt text, return combined list."""
    all_entries: list[dict] = []

    if include_xstest:
        all_entries.extend(load_xstest())
    if include_wildjailbreak:
        all_entries.extend(load_wildjailbreak())
    if include_deepset:
        all_entries.extend(load_deepset_injections())

    # Deduplicate by normalized prompt text (keep first occurrence)
    seen: set[str] = set()
    deduped: list[dict] = []
    for entry in all_entries:
        key = entry["prompt"].strip().lower()
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    dupes = len(all_entries) - len(deduped)
    if dupes:
        logger.info(f"Removed {dupes} duplicate entries after combining datasets")

    logger.info(f"Total evaluation entries: {len(deduped)}")
    return deduped
