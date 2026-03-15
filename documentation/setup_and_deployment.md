# IronGuard Setup & Deployment Guide

This guide provides comprehensive instructions for deploying IronGuard in various environments, from local development to production-ready Docker setups.

## 1. Local Development (Standard)

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- MongoDB & ChromaDB (via Docker or local install)

### Backend Setup
1.  Navigate to `ironguard_backend`.
2.  Create a virtual environment: `python -m venv venv`.
3.  Activate it: `source venv/bin/activate` (Mac/Linux) or `venv\Scripts\activate` (Windows).
4.  Install dependencies: `pip install -r requirements.txt`.
5.  Launch the server: `uvicorn main:app --reload --port 8000`.

### Frontend Setup
1.  Navigate to `frontend`.
2.  Install dependencies: `npm install`.
3.  Start the development server: `npm run dev`.
4.  Access the dashboard at `http://localhost:5173`.

---

## 2. Docker Deployment (Recommended)

Docker is the preferred way to run IronGuard as it ensures all security models and database dependencies are correctly configured.

### Commands
- **Start everything**: `docker compose up --build -d`
- **View logs**: `docker compose logs -f backend`
- **Stop system**: `docker compose down`

### Environment Variables
Modify the `.env` file in the root or backend directory to configure:
- `MONGO_URI`: Connection string for MongoDB.
- `CHROMA_HOST`: Hostname for the ChromaDB container.
- `OPENAI_API_KEY`: Required if using the LLM Proxy features.

---

## 3. Production Hardening

When deploying IronGuard to a production environment (e.g., AWS, GCP, Azure), consider the following:

### Infrastructure
- **GPU Acceleration**: For high-traffic production use, we recommend using a GPU for the `Intent Classifier` and `SentenceTransformer` layers. Update the `device` parameter in `app/threat_detection/intent_classifier.py` from `-1` (CPU) to `0` (GPU).
- **Persistent Volumes**: Ensure that Docker volumes for MongoDB (`mongodb_data`) and ChromaDB (`chroma_data`) are backed up regularly.

### Security
- **API Authentication**: Protect the IronGuard administrative endpoints using a reverse proxy (like Nginx or Traefik) with proper SSL/TLS and API key validation.
- **Network Isolation**: Ensure the databases (MongoDB/ChromaDB) are only accessible to the IronGuard backend container and not exposed to the public internet.

## 4. Troubleshooting

### Model Loading Delay
The first time you start IronGuard, it may take several minutes to download the 500MB+ security models from Hugging Face. We have optimized this in our `Dockerfile` by pre-caching these models during the build phase.

### "Dataset not found" Errors
If `init_dataset.py` fails to download datasets from Hugging Face, check your container's internet connectivity or verify if the dataset paths on the Hub have changed.
