from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from app.database.mongodb import get_database
from app.api.auth import RoleChecker
from app.models.schemas import Role, UserRoleUpdate
from app.monitoring.user_manager import user_manager

router = APIRouter(prefix="/analytics", tags=["analytics"])

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
        
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    pipeline = [
        {"$match": {"timestamp": {"$gte": thirty_days_ago}}},
        {"$group": {
            "_id": {
                "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "action": "$action_taken"
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.date": 1}},
    ]
    
    cursor = db.threat_logs.aggregate(pipeline)
    results = await cursor.to_list(length=300)
    
    # Process results into a format suitable for the frontend (e.g., Chart.js)
    dates = sorted(list(set(r["_id"]["date"] for r in results)))
    actions = list(set(r["_id"]["action"] for r in results))
    
    datasets = []
    for action in actions:
        data = []
        for d in dates:
            count = next((r["count"] for r in results if r["_id"]["date"] == d and r["_id"]["action"] == action), 0)
            data.append(count)
        datasets.append({"label": action, "data": data})
        
    return {
        "labels": dates,
        "datasets": datasets
    }

@router.get("/top-threats", dependencies=[admin_only])
async def get_top_threats():
    db = get_database()
    if db is None:
         return {"data": "Database not connected"}
         
    pipeline = [
        {"$unwind": "$attack_types"},
        {"$group": {"_id": "$attack_types", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    
    cursor = db.threat_logs.aggregate(pipeline)
    results = await cursor.to_list(length=10)
    
    return {r["_id"]: r["count"] for r in results}

@router.get("/risk-distribution", dependencies=[admin_only])
async def get_risk_distribution():
    db = get_database()
    if db is None:
        return {"data": "Database not connected"}
        
    pipeline = [
        {"$bucket": {
            "groupBy": "$risk_score",
            "boundaries": [0, 30, 60, 101],
            "default": "Unknown",
            "output": {"count": {"$sum": 1}}
        }}
    ]
    
    cursor = db.threat_logs.aggregate(pipeline)
    results = await cursor.to_list(length=10)
    
    mapping = {0: "Safe", 30: "Suspicious", 60: "Malicious"}
    return {mapping.get(r["_id"], "Other"): r["count"] for r in results}

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
@router.get("/users", dependencies=[admin_only])
async def get_users():
    """
    Fetch all users and their summarized security stats.
    """
    db = get_database()
    if db is None:
        return {"users": []}

    # Fetch all trust scores
    cursor = db.trust_scores.find()
    users = await cursor.to_list(length=100)

    result = []
    for user in users:
        user_id = user.get("user_id")
        
        # Aggregate stats for this specific user from threat_logs
        stats_cursor = db.threat_logs.aggregate([
            {"$match": {"user_id": user_id}},
            {"$group": {
                "_id": "$user_id",
                "total_checked": {"$sum": 1},
                "sanitized": {"$sum": {"$cond": [{"$in": ["$action_taken", ["Sanitized", "Passed"]]}, 1, 0]}},
                "blocked": {"$sum": {"$cond": [{"$eq": ["$action_taken", "Blocked"]}, 1, 0]}},
            }}
        ])
        
        agg_stats_list = await stats_cursor.to_list(length=1)
        agg_stats = agg_stats_list[0] if agg_stats_list else {}

        result.append({
            "user_id": user_id,
            "role": user.get("role", "employee"),
            "trust_score": user.get("trust_score", 100),
            "total_checked": agg_stats.get("total_checked", 0),
            "sanitized": agg_stats.get("sanitized", 0),
            "blocked": agg_stats.get("blocked", 0),
            "email": user.get("email") or (f"{user_id}@ironguard.ai" if "user_" in user_id else "admin@ironguard.ai"),
            "full_name": user.get("full_name")
        })

    return {"users": result}
@router.get("/metrics/latency-breakdown", dependencies=[admin_only])
async def get_latency_metrics():
    db = get_database()
    if db is None:
        return {"data": "Database not connected"}
    
    pipeline = [
        {"$group": {
            "_id": None,
            "avg_latency": {"$avg": "$classifier_output.latency_ms"},
            "max_latency": {"$max": "$classifier_output.latency_ms"},
            "p95_latency": {"$percentile": {"input": "$classifier_output.latency_ms", "p": [95], "method": "approximate"}}
        }}
    ]
    cursor = db.threat_logs.aggregate(pipeline)
    results = await cursor.to_list(length=1)
    return results[0] if results else {}

@router.get("/metrics/blocking-efficiency", dependencies=[admin_only])
async def get_blocking_efficiency():
    db = get_database()
    if db is None:
        return {"data": "Database not connected"}
    
    pipeline = [
        {"$group": {
            "_id": "$action_taken",
            "count": {"$sum": 1}
        }}
    ]
    cursor = db.threat_logs.aggregate(pipeline)
    results = await cursor.to_list(length=10)
    return {r["_id"]: r["count"] for r in results}

@router.get("/metrics/sanitization-ratio", dependencies=[admin_only])
async def get_sanitization_ratio():
    db = get_database()
    if db is None:
        return {"data": "Database not connected"}
    
    total = await db.threat_logs.count_documents({})
    if total == 0: return {"ratio": 0}
    
    sanitized = await db.threat_logs.count_documents({"action_taken": "Sanitized"})
    return {"ratio": (sanitized / total) * 100, "sanitized": sanitized, "total": total}

@router.get("/metrics/top-policy-violations", dependencies=[admin_only])
async def get_top_policy_violations():
    db = get_database()
    if db is None:
        return {"data": "Database not connected"}
    
    pipeline = [
        {"$unwind": "$reasons"},
        {"$group": {"_id": "$reasons", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    cursor = db.threat_logs.aggregate(pipeline)
    results = await cursor.to_list(length=5)
    return {r["_id"]: r["count"] for r in results}
