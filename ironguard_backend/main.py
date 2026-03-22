from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import os
import time
import logging
print("\n" + "="*50 + "\n🚀 IRON_GUARD BACKEND V10 STARTING\n" + "="*50 + "\n")
from datetime import datetime

from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.database.chromadb import chroma_manager
from app.api import endpoints, admin, gateway_admin
from app.gateway import endpoints as gateway_endpoints


@asynccontextmanager
async def lifespan(app: FastAPI):
    import logging
    logger = logging.getLogger("ironguard.startup")

    # 1. Databases — always first
    await connect_to_mongo()
    chroma_manager.connect()
    
    # Add MongoDB indexes (Fix 5)
    from app.database.mongodb import get_database
    db = get_database()
    if db is not None:
        await db.threat_logs.create_index([("user_id", 1), ("timestamp", -1)])
        await db.sessions.create_index([("session_id", 1)])
        await db.sessions.create_index([("last_updated", 1)], expireAfterSeconds=86400)
        await db.gateway_clients.create_index([("client_id", 1)], unique=True)
        await db.gateway_clients.create_index([("is_active", 1)])
        await db.gateway_request_log.create_index([("client_id", 1), ("timestamp", -1)])
        
        # New: Invite indexes
        await db.invites.create_index([("user_id", 1), ("status", 1)])
        await db.invites.create_index([("expires_at", 1)], expireAfterSeconds=0) # Auto-delete expired
        
        # Seed System Dashboard Client (MOD-6 Gateway Enforcement)
        import os
        from app.gateway.signing import encrypt_secret
        dashboard_id = "SYSTEM_DASHBOARD"
        dashboard_secret = os.getenv("SYSTEM_DASHBOARD_SECRET", "default_secret_change_me")
        
        # Nuclear Re-seed: Ensure field names are correct (encrypted_secret, request_count)
        await db.gateway_clients.delete_one({"client_id": dashboard_id})
        await db.gateway_clients.insert_one({
            "client_id": dashboard_id,
            "encrypted_secret": encrypt_secret(dashboard_secret),
            "client_name": "IronGuard Internal Dashboard",
            "is_active": True,
            "request_count": 0,
            "created_at": datetime.utcnow()
        })
        logger.info(f"🚀 SYSTEM CLIENT RE-SEEDED: {dashboard_id}")
        
        # Dev Convenience: Clear verification lockouts on restart
        await db.verification_attempts.delete_many({})
        await db.lockouts.delete_many({})
        logger.info("🔓 Lockouts cleared for development test")
    
    logger.info("✓ Databases connected + Indexes created + System Client provisioned")

    # 2. Intent Classifier — heavy model, warm up in background (non-blocking)
    from app.threat_detection.intent_classifier import intent_classifier
    asyncio.create_task(intent_classifier.initialize())
    logger.info("⏳ Intent classifier warming up in background...")

    # 3. MOD-3: Fingerprint Engine — load JSON + construct MinHashLSH
    #    Must complete before serving (synchronous, ~200ms on cold start)
    from app.fingerprinting.fingerprint_engine import fingerprint_engine
    from app.threat_detection.semantic import semantic_analyzer  # model loads at import
    fingerprint_engine._load_db()
    fingerprint_engine.set_encoder(semantic_analyzer.model)  # BUG-3 fix
    logger.info(f"✓ Fingerprint engine loaded ({len(fingerprint_engine.simhash_store)} entries) + encoder attached")

    # 4. MOD-2: Response Monitor — verify all regex patterns compiled correctly
    from app.response_security.response_monitor import response_monitor
    response_monitor.verify_patterns()
    logger.info("✓ Response scanner patterns verified")

    # 5. MOD-4: Semantic Sanitizer — initialise (shares encoder with classifier)
    from app.sanitization.sanitizer import semantic_sanitizer
    semantic_sanitizer.initialize(encoder=semantic_analyzer.model)  # BUG-4 fix
    logger.info("✓ Semantic sanitizer initialized with encoder")

    # 6. Seed ChromaDB attack dataset in background (non-blocking, existing behavior)
    from seed_data.init_dataset import initialize_dataset_background
    asyncio.create_task(initialize_dataset_background())
    logger.info("⏳ ChromaDB seed task started in background")

    yield

    await close_mongo_connection()
    logger.info("IronGuard shutdown complete")


app = FastAPI(
    title="IronGuard AI Security Firewall",
    description="Hybrid AI security middleware: Regex + Semantic + Intent Classifier.",
    version="2.0.0",
    lifespan=lifespan,
)

from app.gateway.middleware import GatewaySignatureMiddleware
app.add_middleware(GatewaySignatureMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(endpoints.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1/analytics")
app.include_router(gateway_endpoints.router, prefix="/gateway/v1")
app.include_router(gateway_admin.router)


@app.get("/")
async def root():
    return {"service": "IronGuard API", "status": "online", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)