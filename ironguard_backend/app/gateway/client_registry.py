"""
app/gateway/client_registry.py
================================
MongoDB-backed registry of authorized backend clients.
Raw secrets are encrypted with Fernet before storage.
DB field: encrypted_secret (not hashed_secret — the value IS decryptable
at runtime using IG_SECRET_ENCRYPTION_KEY, which is never in the DB).
"""

import logging
import uuid
from datetime import datetime
from typing import Optional
from app.database.mongodb import get_database
from app.gateway.signing import generate_secret, encrypt_secret, decrypt_secret

logger = logging.getLogger(__name__)


class GatewayClientRegistry:

    async def register_client(
        self, client_name: str, created_by: str, allowed_rpm: int = 60
    ) -> dict:
        """
        Register a new backend client.
        Returns client_id and RAW secret (shown once — client stores it,
        IronGuard stores only the encrypted version).
        """
        db = get_database()
        client_id = str(uuid.uuid4())
        raw_secret = generate_secret()
        encrypted = encrypt_secret(raw_secret)  # ← Fernet encrypt, not hash

        await db.gateway_clients.insert_one({
            "client_id": client_id,
            "client_name": client_name,
            "encrypted_secret": encrypted,   # ← field name updated
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_used": None,
            "request_count": 0,
            "allowed_rpm": allowed_rpm,
            "created_by": created_by,
            "revoked_at": None,
            "revoke_reason": None,
        })

        logger.info(f"Registered gateway client: {client_name} ({client_id})")
        return {
            "client_id": client_id,
            "client_name": client_name,
            "secret": raw_secret,   # shown ONCE — not stored raw
            "warning": "Store this secret securely. It will not be shown again.",
        }

    async def get_client(self, client_id: str) -> Optional[dict]:
        """Fetch active client record."""
        db = get_database()
        return await db.gateway_clients.find_one(
            {"client_id": client_id, "is_active": True},
            {"_id": 0}
        )

    async def get_decrypted_secret(self, client_id: str) -> Optional[str]:
        """
        Fetch and decrypt the signing secret for a client.
        Returns None if client not found, inactive, or decryption fails.
        """
        client = await self.get_client(client_id)
        if not client:
            logger.warning(f"Gateway verify failed: Client {client_id} not found or inactive")
            return None
            
        secret = client.get("encrypted_secret")
        if not secret:
            logger.error(f"Gateway CRITICAL: Client {client_id} missing 'encrypted_secret' field in DB")
            return None
            
        return decrypt_secret(secret)

    async def record_usage(self, client_id: str) -> None:
        """Fire-and-forget usage tracking."""
        db = get_database()
        await db.gateway_clients.update_one(
            {"client_id": client_id},
            {"$set": {"last_used": datetime.utcnow()}, "$inc": {"request_count": 1}},
        )

    async def rotate_secret(self, client_id: str) -> dict:
        """Generate new signing secret. Old secret immediately invalidated."""
        db = get_database()
        raw_secret = generate_secret()
        encrypted = encrypt_secret(raw_secret)

        result = await db.gateway_clients.update_one(
            {"client_id": client_id, "is_active": True},
            {"$set": {"encrypted_secret": encrypted, "last_used": None}}
        )
        if result.matched_count == 0:
            return {"error": "Client not found or inactive"}

        logger.info(f"Rotated secret for gateway client: {client_id}")
        return {
            "client_id": client_id,
            "new_secret": raw_secret,
            "warning": "Store this secret securely. It will not be shown again.",
        }

    async def revoke_client(self, client_id: str, reason: str, revoked_by: str) -> bool:
        """Deactivate a client permanently."""
        db = get_database()
        result = await db.gateway_clients.update_one(
            {"client_id": client_id},
            {"$set": {
                "is_active": False,
                "revoked_at": datetime.utcnow(),
                "revoke_reason": reason,
            }}
        )
        logger.warning(f"Revoked gateway client {client_id} by {revoked_by}: {reason}")
        return result.modified_count > 0

    async def list_clients(self) -> list[dict]:
        """List all clients. encrypted_secret never returned."""
        db = get_database()
        cursor = db.gateway_clients.find(
            {},
            {"_id": 0, "encrypted_secret": 0}   # never expose encrypted value
        ).sort("created_at", -1)
        return await cursor.to_list(length=100)


client_registry = GatewayClientRegistry()
