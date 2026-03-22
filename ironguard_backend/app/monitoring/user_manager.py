import logging
import os
import secrets
from typing import Optional, List
from datetime import datetime, timedelta
import hashlib
import binascii
from app.database.mongodb import get_database
from app.models.schemas import Role, UserTrustScore

logger = logging.getLogger(__name__)

class UserManager:
    def __init__(self):
        self._collection_name = "trust_scores"
        self._invites_collection = "invites"
        # 1-hour TTL cache for verification status to reduce DB hits on hot paths
        self._verified_cache = {} # {user_id: (is_verified, expiry_time)}

    def _hash_token(self, token: str) -> str:
        salt = secrets.token_hex(8)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', token.encode(), salt.encode(), 100000)
        return f"pbkdf2:sha256:100000${salt}${binascii.hexlify(pwd_hash).decode()}"

    def _verify_token(self, token: str, hashed: str) -> bool:
        try:
            parts = hashed.split('$')
            if len(parts) != 3: return False
            _, salt, expected_hash = parts
            pwd_hash = hashlib.pbkdf2_hmac('sha256', token.encode(), salt.encode(), 100000)
            return binascii.hexlify(pwd_hash).decode() == expected_hash
        except Exception:
            return False

    def _is_admin_check(self, user_id: str) -> bool:
        """Helper to check if a user is an admin from env."""
        user_id = user_id.strip().lower()
        admin_ids_str = os.getenv("ADMIN_USER_IDS", "")
        # Normalize comparison list to lowercase
        admin_ids = [uid.strip().lower() for uid in admin_ids_str.split(",") if uid.strip()]
        
        # Diagnostic: Only log if not found to avoid excessive noise
        if user_id not in admin_ids:
             print(f"[DEBUG] User {user_id} not in ADMIN_USER_IDS: {admin_ids}")
             
        return user_id in admin_ids

    async def get_user_role(self, user_id: str, email: Optional[str] = None, full_name: Optional[str] = None) -> Role:
        """
        Retrieves the role for a given user_id. 
        Priority: .env ADMIN_USER_IDS > Database stored role.
        """
        if self._is_admin_check(user_id):
            return Role.ADMIN

        db = get_database()
        if db is None:
            return Role.EMPLOYEE

        user_data = await db[self._collection_name].find_one({"user_id": user_id})
        
        if not user_data:
            # Check if any users exist in the system (Bootstrap)
            existing_count = await db[self._collection_name].count_documents({})
            role = Role.ADMIN if existing_count == 0 else Role.EMPLOYEE
            
            new_user = UserTrustScore(user_id=user_id, role=role, email=email, full_name=full_name)
            user_dict = new_user.model_dump()
            # New employees start as unverified
            user_dict["is_verified"] = False if role == Role.EMPLOYEE else True
            
            await db[self._collection_name].insert_one(user_dict)
            return role
        
        # Sync profile if needed
        updates = {}
        if email and user_data.get("email") != email:
            updates["email"] = email
        if full_name and user_data.get("full_name") != full_name:
            updates["full_name"] = full_name
        
        if updates:
            await db[self._collection_name].update_one({"user_id": user_id}, {"$set": updates})

        return Role(user_data.get("role", Role.EMPLOYEE))

    async def is_user_verified(self, user_id: str) -> bool:
        """Check if a user is verified (with 1h TTL cache). Admin is always verified."""
        if self._is_admin_check(user_id):
            return True

        # Check Cache
        now = datetime.utcnow()
        if user_id in self._verified_cache:
            val, expiry = self._verified_cache[user_id]
            if now < expiry:
                return val

        db = get_database()
        if db is None: return False

        user = await db[self._collection_name].find_one({"user_id": user_id})
        is_verified = user.get("is_verified", False) if user else False
        
        # Update Cache (1 hour)
        self._verified_cache[user_id] = (is_verified, now + timedelta(hours=1))
        return is_verified

    async def create_invite(self, user_id: str) -> str:
        """Generates a secure token, hashes it with bcrypt, and stores in DB."""
        db = get_database()
        if db is None: return ""

        plain_token = secrets.token_hex(8) # exactly 16 chars
        hashed_token = self._hash_token(plain_token)
        
        invite_doc = {
            "user_id": user_id,
            "hashed_secret": hashed_token,
            "status": "pending",
            "expires_at": datetime.utcnow() + timedelta(days=7),
            "created_at": datetime.utcnow()
        }

        await db[self._invites_collection].update_one(
            {"user_id": user_id, "status": "pending"},
            {"$set": {"status": "expired"}}, # Invalidate any old pending invites
            upsert=False
        )
        
        await db[self._invites_collection].insert_one(invite_doc)
        return plain_token

    async def verify_invite(self, user_id: str, plain_token: str) -> bool:
        """
        Atomic verification: find_one_and_update ensures no race-condition replays.
        Uses constant-time bcrypt verification.
        """
        db = get_database()
        if db is None: return False

        # 1. Find pending invite
        invite = await db[self._invites_collection].find_one({
            "user_id": user_id,
            "status": "pending",
            "expires_at": {"$gt": datetime.utcnow()}
        })

        if not invite:
            return False

        # 2. Verify hash
        if not self._verify_token(plain_token, invite["hashed_secret"]):
            return False

        # 3. Atomic Update: Mark as used
        result = await db[self._invites_collection].find_one_and_update(
            {"_id": invite["_id"], "status": "pending"},
            {"$set": {"status": "used", "used_at": datetime.utcnow()}}
        )

        if result:
            # 4. Success: Update user verification status
            await db[self._collection_name].update_one(
                {"user_id": user_id},
                {"$set": {"is_verified": True}}
            )
            # Invalidate cache
            self._verified_cache.pop(user_id, None)
            return True
        
        return False

    async def assign_role(self, user_id: str, role: Role):
        db = get_database()
        if db is None: return False

        result = await db[self._collection_name].update_one(
            {"user_id": user_id},
            {"$set": {"role": role, "last_updated": datetime.utcnow()}},
            upsert=True
        )
        return result.modified_count > 0 or result.upserted_id is not None

    async def get_user_stats(self, user_id: str):
        db = get_database()
        if db is None: return None

        user_trust = await db[self._collection_name].find_one({"user_id": user_id})
        if not user_trust:
            return {"total_checked": 0, "sanitized": 0, "blocked": 0, "trust_score": 100, "malicious_attempts": 0}

        total_checked = await db.threat_logs.count_documents({"user_id": user_id})
        sanitized = await db.threat_logs.count_documents({
            "user_id": user_id, 
            "action_taken": {"$in": ["Sanitized", "Passed", "Allowed"]}
        })
        blocked = await db.threat_logs.count_documents({"user_id": user_id, "action_taken": "Blocked"})

        return {
            "total_checked": total_checked,
            "sanitized": sanitized,
            "blocked": blocked,
            "trust_score": user_trust.get("trust_score", 100),
            "malicious_attempts": user_trust.get("malicious_attempts", 0)
        }

user_manager = UserManager()
