from datetime import datetime, timedelta
import logging
from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger(__name__)
from app.database.mongodb import get_database
from app.api.auth import RoleChecker
from app.models.schemas import Role, UserRoleUpdate
from app.monitoring.user_manager import user_manager

router = APIRouter(tags=["analytics"])

@router.get("/ping")
async def ping():
    return {"status": "ok", "from": "admin"}

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
    
    # Fetch all latency values to calculate percentile in Python (Mongo 6.0 compat)
    cursor = db.threat_logs.find({}, {"classifier_output.latency_ms": 1})
    logs = await cursor.to_list(length=1000)
    
    latencies = [log.get("classifier_output", {}).get("latency_ms", 0) for log in logs if log.get("classifier_output", {}).get("latency_ms") is not None]
    
    if not latencies:
        return {"avg_latency": 0, "max_latency": 0, "p95_latency": 0}
        
    latencies.sort()
    count = len(latencies)
    avg_latency = sum(latencies) / count
    max_latency = latencies[-1]
    p95_index = min(int(count * 0.95), count - 1)
    p95_latency = latencies[p95_index]
    
    return {
        "avg_latency": avg_latency,
        "max_latency": max_latency,
        "p95_latency": p95_latency
    }

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


@router.get("/logs", dependencies=[admin_only])
async def get_logs(limit: int = 50):
    """
    Fetch recent security event logs.
    """
    db = get_database()
    if db is None:
        return {"logs": []}
    
    cursor = db.threat_logs.find().sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)
    
    for log in logs:
        log["_id"] = str(log["_id"])
        if isinstance(log.get("timestamp"), datetime):
            log["timestamp"] = log["timestamp"].isoformat()
            
    return {"logs": logs}
    

@router.get("/fingerprints", dependencies=[admin_only])
async def get_fingerprints():
    """
    Fetch all known and autonomously learned threat fingerprints.
    """
    from app.fingerprinting.fingerprint_engine import FINGERPRINT_DB_PATH
    import json
    import os
    
    logger.info(f"Fetching fingerprints from: {FINGERPRINT_DB_PATH.absolute()}")
    
    if not FINGERPRINT_DB_PATH.exists():
        logger.warning(f"Fingerprint DB not found at {FINGERPRINT_DB_PATH.absolute()}")
        return {"fingerprints": [], "warning": "Database file not found"}
        
    try:
        content = FINGERPRINT_DB_PATH.read_text(encoding="utf-8")
        data = json.loads(content)
        jailbreaks = data.get("jailbreaks", [])
        logger.info(f"Successfully loaded {len(jailbreaks)} fingerprints")
        return {"fingerprints": jailbreaks}
    except Exception as e:
        logger.error(f"Failed to read fingerprint DB: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to read fingerprints: {str(e)}")


from app.security_engine.key_vault import key_vault
from app.models.schemas import ProviderKeyUpdate, ProviderKeyResponse
from typing import List

@router.post("/keys", dependencies=[admin_only])
async def store_provider_key(update: ProviderKeyUpdate):
    """
    Securely store or update an AI provider API key.
    """
    success = await key_vault.set_key(update.provider, update.api_key)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to store provider key")
    return {"message": f"Successfully stored key for {update.provider}"}

@router.get("/keys", response_model=List[ProviderKeyResponse], dependencies=[admin_only])
async def list_provider_keys():
    """
    List all configured providers (keys are never shown).
    """
    return await key_vault.list_keys()

@router.delete("/keys/{provider}", dependencies=[admin_only])
async def delete_provider_key(provider: str):
    """
    Revoke/delete a provider key.
    """
    success = await key_vault.delete_key(provider)
    if not success:
        raise HTTPException(status_code=404, detail=f"No key found for provider {provider}")
    return {"message": f"Successfully revoked key for {provider}"}
