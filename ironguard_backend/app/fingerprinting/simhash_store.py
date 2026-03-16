# app/fingerprinting/simhash_store.py
from typing import Optional, Tuple


def _hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two integers via XOR popcount."""
    return bin(a ^ b).count("1")


class SimHashStore:
    """
    In-memory store of (hash_int, canonical_form) pairs.
    Exposes query() via XOR Hamming distance comparison.
    """
    def __init__(self):
        self._store: list[tuple[int, str]] = []

    def add(self, canonical_form: str, hash_val: int) -> None:
        self._store.append((hash_val, canonical_form))

    def query(self, hash_val: int, threshold: int) -> Tuple[Optional[int], Optional[str]]:
        """
        Returns (hamming_distance, canonical_form) for the closest stored hash
        within `threshold` bits, or (None, None) if nothing matches.
        """
        best_distance = threshold + 1
        best_canonical = None
        for stored_hash, canonical in self._store:
            d = _hamming_distance(hash_val, stored_hash)
            if d <= threshold and d < best_distance:
                best_distance = d
                best_canonical = canonical
        if best_canonical is not None:
            return best_distance, best_canonical
        return None, None

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
