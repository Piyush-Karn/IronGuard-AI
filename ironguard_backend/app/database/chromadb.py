import chromadb
from chromadb.config import Settings as ChromaSettings
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    CHROMA_HOST: str = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT: str = os.getenv("CHROMA_PORT", "8000")
    COLLECTION_NAME: str = "attack_patterns"

settings = Settings()

class ChromaDBManager:
    def __init__(self):
        self.client = None
        self.collection = None

    def connect(self):
        print(f"Connecting to ChromaDB at {settings.CHROMA_HOST}:{settings.CHROMA_PORT}")
        self.client = chromadb.HttpClient(
            host=settings.CHROMA_HOST, 
            port=int(settings.CHROMA_PORT)
        )
        self.collection = self.client.get_or_create_collection(name=settings.COLLECTION_NAME)

    def get_collection(self):
        if not self.collection:
            self.connect()
        return self.collection

chroma_manager = ChromaDBManager()
