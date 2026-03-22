from app.database.chromadb import chroma_manager
from app.threat_detection.semantic import semantic_analyzer
from typing import Tuple, List

class SimilarityDetector:
    def __init__(self, threshold: float = 0.92):
        self.threshold = threshold

    def detect(self, prompt: str) -> Tuple[bool, List[str], List[str]]:
        collection = chroma_manager.get_collection()
        embedding = semantic_analyzer.generate_embedding(prompt)
        
        # Query ChromaDB
        results = collection.query(
            query_embeddings=[embedding],
            n_results=3,
            include=['distances', 'metadatas']
        )
        
        is_suspicious = False
        reasons = []
        attack_types = []
        
        if not results['distances'] or not results['distances'][0]:
            return False, [], []
            
        distances = results['distances'][0]
        metadatas = results['metadatas'][0]
        
        for i, distance in enumerate(distances):
            # ChromaDB cosine distance: smaller means more similar
            # If using l2, need to convert to similarity score depending on distance metric
            # Assuming distance here is L2, typically sim = 1 - (dist / 2) for normalized vectors
            # Let's assume a simpler check: if distance is small enough
            similarity_score = 1.0 - distance
            
            if similarity_score >= self.threshold:
                is_suspicious = True
                meta = metadatas[i] if metadatas else {}
                attack_type = meta.get("attack_type", "Unknown")
                
                reasons.append(f"High similarity ({similarity_score:.2f}) to known attack in database")
                if attack_type not in attack_types:
                    attack_types.append(attack_type)
                    
        return is_suspicious, reasons, attack_types

similarity_detector = SimilarityDetector()
