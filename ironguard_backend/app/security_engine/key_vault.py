import os
import logging
from datetime import datetime
from typing import Optional, List
from cryptography.fernet import Fernet
from app.database.mongodb import get_database
from app.models.schemas import ProviderKeyResponse

logger = logging.getLogger(__name__)

class KeyVault:
    def __init__(self):
        # Fallback to a default key if not found (but log a warning)
        secret = os.getenv("IG_SECRET_ENCRYPTION_KEY")
        if not secret:
            logger.error("IG_SECRET_ENCRYPTION_KEY not found in environment!")
            # Using a stable but "unsafe" fallback if env is missing to prevent total crash
            # In production, this should always be provided.
            secret = "eDFljg4F62MiSIOhy1lmEXgCciuCmAvrlV8DGDoTkIk=" 
        
        try:
            self.fernet = Fernet(secret.encode())
        except Exception as e:
            logger.error(f"Failed to initialize Fernet: {e}")
            self.fernet = None

    async def set_key(self, provider: str, api_key: str) -> bool:
        if not self.fernet:
            logger.error("KeyVault not initialized (Fernet missing)")
            return False
            
        db = get_database()
        if db is None:
            logger.error("Database connection missing for KeyVault")
            return False
            
        try:
            encrypted = self.fernet.encrypt(api_key.encode()).decode()
            
            await db.provider_keys.update_one(
                {"provider": provider.lower()},
                {
                    "$set": {
                        "encrypted_key": encrypted,
                        "updated_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
            logger.info(f"Successfully stored/updated encrypted key for provider: {provider}")
            return True
        except Exception as e:
            logger.error(f"Failed to store key for {provider}: {e}")
            return False

    async def get_key(self, provider: str) -> Optional[str]:
        if not self.fernet:
            return None
            
        db = get_database()
        if db is None:
            return None
            
        try:
            doc = await db.provider_keys.find_one({"provider": provider.lower()})
            if not doc:
                return None
                
            decrypted = self.fernet.decrypt(doc["encrypted_key"].encode()).decode()
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt key for {provider}: {e}")
            return None

    async def list_keys(self) -> List[ProviderKeyResponse]:
        db = get_database()
        if db is None:
            return []
            
        try:
            cursor = db.provider_keys.find()
            keys = await cursor.to_list(length=100)
            
            return [
                ProviderKeyResponse(
                    provider=k["provider"],
                    is_active=True,
                    updated_at=k["updated_at"]
                )
                for k in keys
            ]
        except Exception as e:
            logger.error(f"Failed to list keys: {e}")
            return []

    async def delete_key(self, provider: str) -> bool:
        db = get_database()
        if db is None:
            return False
            
        try:
            result = await db.provider_keys.delete_one({"provider": provider.lower()})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Failed to delete key for {provider}: {e}")
            return False

key_vault = KeyVault()
