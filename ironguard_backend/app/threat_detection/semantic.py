from sentence_transformers import SentenceTransformer
import numpy as np

class SemanticAnalyzer:
    def __init__(self):
        # Using a small models for fast intent classification / embeddings
        self.model = SentenceTransformer('all-MiniLM-L6-v2')

    def generate_embedding(self, text: str) -> list[float]:
        # Generate embedding for the input text
        embedding = self.model.encode([text])[0]
        return embedding.tolist()

semantic_analyzer = SemanticAnalyzer()
