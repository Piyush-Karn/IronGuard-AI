# IronGuard AI Security Firewall

IronGuard is a security middleware platform that protects AI systems from prompt injection attacks, malicious inputs, and adversarial users. It serves as a security layer between end users and Large Language Models (LLMs).

## Architecture
IronGuard implements a **3-Layer Hybrid Detection Pipeline**:
1.  **Layer 1: Pattern Detector**: Regex and fuzzy matching (error-tolerant).
2.  **Layer 2: Semantic Analyzer**: Vector similarity search using ChromaDB (~60k attack vectors).
3.  **Layer 3: Intent Classifier**: Context-aware AI detection using a dedicated transformer model.

For a deep dive into the architecture, see the **[Architecture Documentation](../documentation/architecture.md)**.

## Getting Started

### Prerequisites
- Docker and Docker Compose
- Python 3.11+ (if running locally without Docker)

### Running with Docker (Recommended)
```bash
cd ironguard_backend
docker-compose up --build
```

### Initializing the Attack Dataset
Once ChromaDB is running, you can initialize the vector database with sample attack patterns:
```bash
docker-compose exec backend python datasets/init_dataset.py
```
*(Or simply run `python datasets/init_dataset.py` locally if your environment has the required packages and ChromaDB is accessible).*

### API Endpoints
- **Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- `POST /api/v1/scan_prompt`: Evaluates a prompt's risk without sending it to an LLM.
- `POST /api/v1/process_prompt`: Scans the prompt, sanitizes if suspicious, and forwards it to the configured LLM proxies.
- `GET /api/v1/analytics/*`: Admin dashboards for attack frequency, top threats, and user behavior.

## Technologies Used
- FastAPI
- MongoDB (Motor AsyncIO)
- ChromaDB
- SentenceTransformers
- Pydantic
