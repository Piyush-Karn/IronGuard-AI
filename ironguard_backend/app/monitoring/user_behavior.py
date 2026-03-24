from app.database.mongodb import get_database
from app.models.schemas import UserTrustScore
from datetime import datetime

class UserBehaviorMonitor:
    def __init__(self):
        self._score_cache = {}

    async def get_or_create_trust_score(self, user_id: str) -> UserTrustScore:
        if user_id in self._score_cache:
            return self._score_cache[user_id]
            
        db = get_database()
        if db is None:
            # Fallback for when MongoDB is not connected during testing
            score = UserTrustScore(user_id=user_id)
            self._score_cache[user_id] = score
            return score
            
        collection = db.trust_scores
        record = await collection.find_one({"user_id": user_id})
        
        if record:
            score = UserTrustScore(**record)
            self._score_cache[user_id] = score
            return score
            
        trust_score = UserTrustScore(user_id=user_id)
        # Handle exceptions gracefully if db insert fails so cache still populatess
        try:
            await collection.insert_one(trust_score.model_dump())
        except Exception:
            pass
        self._score_cache[user_id] = trust_score
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
            
            # Update cache immediately for subsequent zero-latency reads
            trust_score.trust_score = new_score
            trust_score.malicious_attempts = new_malicious
            self._score_cache[user_id] = trust_score
            
            try:
                await db.trust_scores.update_one(
                    {"user_id": user_id},
                    {"$set": {
                        "trust_score": new_score,
                        "malicious_attempts": new_malicious,
                        "last_updated": datetime.utcnow()
                    }}
                )
            except Exception:
                pass

    async def should_terminate_session(self, user_id: str) -> bool:
        trust_score = await self.get_or_create_trust_score(user_id)
        print(f"Checking session for {user_id}: Score={trust_score.trust_score}, Attempts={trust_score.malicious_attempts}")
        if trust_score.malicious_attempts >= 3 or trust_score.trust_score <= 0:
            return True
        return False

    async def reset_trust_score(self, user_id: str):
        # Update cache immediately
        if user_id in self._score_cache:
            self._score_cache[user_id].trust_score = 100
            self._score_cache[user_id].malicious_attempts = 0
            
        db = get_database()
        if db is None:
            print("Reset failed: MongoDB not connected")
            return

        print(f"Resetting trust score for user: {user_id}")
        try:
            result = await db.trust_scores.update_one(
                {"user_id": user_id},
                {"$set": {
                    "trust_score": 100,
                    "malicious_attempts": 0,
                    "last_updated": datetime.utcnow()
                }},
                upsert=True
            )
            print(f"Reset result: matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}")
        except Exception:
            pass

user_behavior_monitor = UserBehaviorMonitor()
