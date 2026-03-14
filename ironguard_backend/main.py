from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.database.chromadb import chroma_manager
from app.api import endpoints, admin

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Events
    await connect_to_mongo()
    chroma_manager.connect()
    
    # Optional: Initialize dataset if Chroma is empty
    # from datasets.init_dataset import initialize_dataset
    # initialize_dataset()
    
    yield
    # Shutdown Events
    await close_mongo_connection()

app = FastAPI(
    title="IronGuard AI Security Firewall",
    description="Security middleware platform that protects AI systems from prompt injection attacks, malicious inputs, and adversarial users.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(endpoints.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "service": "IronGuard API",
        "status": "online",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
