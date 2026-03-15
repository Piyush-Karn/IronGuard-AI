from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio

from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.database.chromadb import chroma_manager
from app.api import endpoints, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Connect databases
    await connect_to_mongo()
    chroma_manager.connect()

    # 2. Warm up the intent classifier in background (non-blocking)
    from app.threat_detection.intent_classifier import intent_classifier
    asyncio.create_task(intent_classifier.initialize())

    # 3. Seed ChromaDB attack dataset in background (non-blocking)
    from seed_data.init_dataset import initialize_dataset_background
    asyncio.create_task(initialize_dataset_background())

    yield

    await close_mongo_connection()


app = FastAPI(
    title="IronGuard AI Security Firewall",
    description="Hybrid AI security middleware: Regex + Semantic + Intent Classifier.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(endpoints.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"service": "IronGuard API", "status": "online", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)