import logging
from datetime import datetime
from app.database.mongodb import get_database
from app.models.schemas import Role, UserTrustScore

logger = logging.getLogger(__name__)

class UserManager:
    def __init__(self):
        self._collection_name = "trust_scores"

    async def get_user_role(self, user_id: str) -> Role:
        """
        Retrieves the role for a given user_id. 
        If the user doesn't exist, they are created with Role.EMPLOYEE.
        """
        db = get_database()
        if db is None:
            logger.error("Database not connected while fetching user role")
            return Role.EMPLOYEE

        user_data = await db[self._collection_name].find_one({"user_id": user_id})
        
        if not user_data:
            # Check if any users exist in the system
            existing_count = await db[self._collection_name].count_documents({})
            
            # Bootstrap: The very first user becomes an ADMIN
            role = Role.ADMIN if existing_count == 0 else Role.EMPLOYEE
            
            logger.info(f"Creating new user {user_id} with role: {role}")
            new_user = UserTrustScore(user_id=user_id, role=role)
            await db[self._collection_name].insert_one(new_user.model_dump())
            return role
        
        return Role(user_data.get("role", Role.EMPLOYEE))

    async def assign_role(self, user_id: str, role: Role):
        """
        Updates the role for a specific user_id.
        """
        db = get_database()
        if db is None:
            return False

        result = await db[self._collection_name].update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "role": role,
                    "last_updated": datetime.utcnow()
                }
            },
            upsert=True
        )
        logger.info(f"Assigned role {role} to user {user_id}")
        return result.modified_count > 0 or result.upserted_id is not None

    async def get_user_stats(self, user_id: str):
        """
        Aggregates personal security stats for a specific user.
        """
        db = get_database()
        if db is None:
            return None

        # Get trust score and malicious attempts
        user_trust = await db[self._collection_name].find_one({"user_id": user_id})
        if not user_trust:
            # If user doesn't exist yet, return defaults
            return {
                "total_checked": 0,
                "sanitized": 0,
                "blocked": 0,
                "trust_score": 100,
                "malicious_attempts": 0
            }

        # Aggregate log counts
        total_checked = await db.threat_logs.count_documents({"user_id": user_id})
        sanitized = await db.threat_logs.count_documents({"user_id": user_id, "action_taken": "Sanitized"})
        blocked = await db.threat_logs.count_documents({"user_id": user_id, "action_taken": "Blocked"})

        return {
            "total_checked": total_checked,
            "sanitized": sanitized,
            "blocked": blocked,
            "trust_score": user_trust.get("trust_score", 100),
            "malicious_attempts": user_trust.get("malicious_attempts", 0)
        }

user_manager = UserManager()
