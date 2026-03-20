"""
app/gateway/signing.py
======================
HMAC-SHA256 request signing for IronGuard Gateway.

Secret storage model:
  raw_secret       → client uses as HMAC key (shown once, never stored)
  encrypted_secret = Fernet(IG_SECRET_ENCRYPTION_KEY).encrypt(raw_secret)
  DB stores        → encrypted_secret only

At verify time:
  decrypt(encrypted_secret) → raw_secret → HMAC key
  DB breach alone = useless without IG_SECRET_ENCRYPTION_KEY env var

Signing protocol:
  message   = f"{timestamp}\\n{client_id}\\n{sha256(body_bytes)}"
  signature = HMAC-SHA256(raw_secret, message)
  headers   = X-IG-Client-Id, X-IG-Timestamp, X-IG-Signature
"""

import hashlib
import hmac
import os
import secrets
import time
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

REPLAY_WINDOW_SECONDS = 30


def _get_fernet() -> Fernet:
    """Load Fernet cipher from env. Raises loudly at startup if missing."""
    key = os.getenv("IG_SECRET_ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError(
            "IG_SECRET_ENCRYPTION_KEY not set. "
            "Generate: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())


def generate_secret() -> str:
    """Generate a cryptographically secure 32-byte hex signing secret."""
    return secrets.token_hex(32)


def encrypt_secret(raw_secret: str) -> str:
    """Encrypt raw_secret for DB storage. Returns base64 Fernet token."""
    return _get_fernet().encrypt(raw_secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> Optional[str]:
    """
    Decrypt stored encrypted_secret to raw_secret for HMAC verification.
    Returns None on failure (wrong key, tampered ciphertext).
    """
    try:
        return _get_fernet().decrypt(encrypted_secret.encode()).decode()
    except (InvalidToken, Exception):
        return None


def build_signing_message(timestamp: str, client_id: str, body_bytes: bytes) -> str:
    """Canonical signed message. Body hash prevents tampering."""
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    return f"{timestamp}\n{client_id}\n{body_hash}"


def compute_signature(raw_secret: str, message: str) -> str:
    """Compute HMAC-SHA256. raw_secret used directly as key."""
    return hmac.new(raw_secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_timestamp(timestamp_str: str) -> tuple[bool, str]:
    """Reject requests outside the 30-second replay window."""
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False, "Invalid timestamp — must be Unix integer"
    delta = abs(int(time.time()) - ts)
    if delta > REPLAY_WINDOW_SECONDS:
        return False, f"Timestamp expired: delta={delta}s exceeds {REPLAY_WINDOW_SECONDS}s"
    return True, ""


def verify_signature(
    provided_signature: str,
    raw_secret: str,
    timestamp: str,
    client_id: str,
    body_bytes: bytes,
) -> bool:
    """Constant-time signature check. raw_secret is the decrypted secret."""
    message = build_signing_message(timestamp, client_id, body_bytes)
    expected = compute_signature(raw_secret, message)
    return hmac.compare_digest(provided_signature, expected)
