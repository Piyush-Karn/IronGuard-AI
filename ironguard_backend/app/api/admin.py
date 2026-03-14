from fastapi import APIRouter
from app.database.mongodb import get_database

router = APIRouter(prefix="/analytics", tags=["admin"])

@router.get("/attack-frequency")
async def get_attack_frequency():
    db = get_database()
    if db is None:
        return {"data": "Database not connected"}
        
    # Example aggregation (stubbed for simplicity)
    # Counts attacks by day/hour
    return {
        "labels": ["Mon", "Tue", "Wed", "Thu", "Fri"],
        "datasets": [
            {"label": "Malicious", "data": [12, 19, 3, 5, 2]},
            {"label": "Suspicious", "data": [5, 10, 2, 8, 4]}
        ]
    }

@router.get("/top-threats")
async def get_top_threats():
    db = get_database()
    if db is None:
         return {"data": "Database not connected"}
         
    # Return distribution of attack types
    return {
        "Prompt Injection": 45,
        "System Prompt Leak": 20,
        "Jailbreak Attempt": 25,
        "Policy Bypass": 5,
        "Data Exfiltration": 5
    }

@router.get("/risk-distribution")
async def get_risk_distribution():
    return {
        "Safe": 75,
        "Suspicious": 15,
        "Malicious": 10
    }

@router.get("/user-behavior")
async def get_user_behavior():
    db = get_database()
    if db is None:
         return {"data": "Database not connected"}
         
    # E.g., fetch all users and their trust scores
    cursor = db.trust_scores.find().sort("trust_score", 1).limit(10)
    users = await cursor.to_list(length=10)
    
    # Exclude MongoDB ObjectId for JSON serialization
    for user in users:
        user["_id"] = str(user["_id"])
        
    return {"at_risk_users": users}
