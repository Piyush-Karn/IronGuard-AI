# IronGuard AI Security Firewall

IronGuard is a security middleware platform that protects AI systems from prompt injection attacks, malicious inputs, and adversarial users. It serves as a security layer between end users and Large Language Models (LLMs).

## Architecture
- **API Gateway**: Exposes FastAPI endpoints for prompt scanning, processing, and admin monitoring.
- **Threat Detection Engine**: Scans prompts using Regex Patterns and Semantic Analysis via SentenceTransformers and ChromaDB.
- **Guardrail Integrations**: Orchestrates connections to Guardrails AI, OpenAI Moderation, and LMQL.
- **Decision Engine & Risk Scorer**: Analyzes threats and outputs explainable risk scores (Safe, Suspicious, Malicious) along with specific reasons and attack types.
- **Response Monitor**: Validates outgoing LLM responses for system prompt leakage.

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
