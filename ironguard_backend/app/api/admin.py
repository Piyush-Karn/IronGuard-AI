from fastapi import APIRouter, Depends, HTTPException
from app.database.mongodb import get_database
from app.api.auth import RoleChecker
from app.models.schemas import Role, UserRoleUpdate
from app.monitoring.user_manager import user_manager

router = APIRouter(prefix="/admin", tags=["admin"])

# Dependency to ensure only admins can access these routes
admin_only = Depends(RoleChecker([Role.ADMIN]))

@router.post("/assign-role", dependencies=[admin_only])
async def assign_role(update: UserRoleUpdate):
    """
    Assign a role (Admin/Employee) to a user.
    """
    success = await user_manager.assign_role(update.user_id, update.role)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to update role")
    return {"message": f"Successfully assigned {update.role} to {update.user_id}"}


@router.get("/attack-frequency", dependencies=[admin_only])
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

@router.get("/top-threats", dependencies=[admin_only])
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

@router.get("/risk-distribution", dependencies=[admin_only])
async def get_risk_distribution():
    return {
        "Safe": 75,
        "Suspicious": 15,
        "Malicious": 10
    }

@router.get("/user-behavior", dependencies=[admin_only])
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
