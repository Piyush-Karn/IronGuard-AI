# IronGuard AI Security Gateway

IronGuard is a production-grade security firewall that protects AI systems from prompt injection, data leakage, and adversarial inputs. It acts as a hardened proxy between users and Large Language Models (LLMs).

## Architecture v2
IronGuard implements a **4-Module Hybrid Architecture** orchestrated for low latency and maximum protection:

1.  **MOD-1: Real LLM Proxy**: Routes to free providers (**Gemini Flash**, **Mistral**) with rate limiting and security preambles.
2.  **MOD-2: Response Security**: Scans and redacts API keys, PII, and harm from outgoing LLM responses.
3.  **MOD-3: Fingerprint Engine**: Sub-ms detection of known jailbreaks using SimHash and MinHash LSH.
4.  **MOD-4: Semantic Sanitizer**: Neutralizes suspicious prompts while preserving intent using LLM-based rewriting.

For a deep dive, see the **[Architecture Documentation](../documentation/architecture.md)**.

## Getting Started

### Prerequisites
- Docker and Docker Compose
- API Keys for **Gemini** (Primary) and **Mistral** (Fallback)

### Running with Docker
1. Create a `.env` file in `ironguard_backend/` and add your keys:
   ```env
   GEMINI_API_KEY=your_key
   MISTRAL_API_KEY=your_key
   ```
2. Start the system:
   ```bash
   docker compose up --build -d
   ```

### Initializing the Threat Database
```bash
docker compose exec backend python datasets/init_dataset.py
```

## API Features
- **Parallel Processing**: Uses `asyncio.gather` for minimal security overhead.
- **NFKC Normalization**: Protects against homoglyph and encoding-based bypasses.
- **Explainable Risk Scoring**: Detailed risk breakdowns with primary threat classifications.
- **Admin Dashboard Integration**: Full support for RBAC-based security monitoring and team management.

## Technologies
- **FastAPI** (Async Core)
- **MongoDB** (Persistance)
- **ChromaDB** (Vector Similarity)
- **HuggingFace** (Transformer Models)
- **Mistral/Gemini** (LLM Intelligence)
