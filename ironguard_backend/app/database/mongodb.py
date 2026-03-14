from typing import Any
from motor.motor_asyncio import AsyncIOMotorClient
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_URL: str = os.getenv("MONGO_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = "ironguard"

settings = Settings()

class MongoDB:
    client: AsyncIOMotorClient = None
    db: Any = None

db_manager = MongoDB()

def get_database():
    return db_manager.db

async def connect_to_mongo():
    print(f"Connecting to MongoDB at {settings.MONGO_URL}")
    db_manager.client = AsyncIOMotorClient(settings.MONGO_URL)
    db_manager.db = db_manager.client[settings.DATABASE_NAME]

async def close_mongo_connection():
    if db_manager.client:
        db_manager.client.close()
