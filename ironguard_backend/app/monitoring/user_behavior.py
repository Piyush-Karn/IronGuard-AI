from app.database.mongodb import get_database
from app.models.schemas import UserTrustScore
from datetime import datetime

class UserBehaviorMonitor:
    def __init__(self):
        pass

    async def get_or_create_trust_score(self, user_id: str) -> UserTrustScore:
        db = get_database()
        if db is None:
            # Fallback for when MongoDB is not connected during testing
            return UserTrustScore(user_id=user_id)
            
        collection = db.trust_scores
        record = await collection.find_one({"user_id": user_id})
        
        if record:
            return UserTrustScore(**record)
            
        trust_score = UserTrustScore(user_id=user_id)
        await collection.insert_one(trust_score.model_dump())
        return trust_score

    async def update_trust_score(self, user_id: str, classification: str):
        db = get_database()
        if db is None:
            return

        trust_score = await self.get_or_create_trust_score(user_id)
        
        score_change = 0
        malicious_inc = 0
        
        if classification == "Suspicious":
            score_change = -5
        elif classification == "Malicious":
            score_change = -15
            malicious_inc = 1
            
        if score_change != 0 or malicious_inc != 0:
            new_score = max(0, trust_score.trust_score + score_change)
            new_malicious = trust_score.malicious_attempts + malicious_inc
            
            await db.trust_scores.update_one(
                {"user_id": user_id},
                {"$set": {
                    "trust_score": new_score,
                    "malicious_attempts": new_malicious,
                    "last_updated": datetime.utcnow()
                }}
            )

    async def should_terminate_session(self, user_id: str) -> bool:
        trust_score = await self.get_or_create_trust_score(user_id)
        if trust_score.malicious_attempts >= 3 or trust_score.trust_score <= 0:
            return True
        return False

    async def reset_trust_score(self, user_id: str):
        db = get_database()
        if db is None:
            return

        await db.trust_scores.update_one(
            {"user_id": user_id},
            {"$set": {
                "trust_score": 100,
                "malicious_attempts": 0,
                "last_updated": datetime.utcnow()
            }}
        )

user_behavior_monitor = UserBehaviorMonitor()
