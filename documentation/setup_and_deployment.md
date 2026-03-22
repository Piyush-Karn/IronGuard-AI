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
- **Restart (applied changes)**: `docker compose restart backend`
- **View logs**: `docker compose logs -f backend`

### Environment Variables (.env)
- `GEMINI_API_KEY`: Google AI key for primary detection and sanitization.
- `MISTRAL_API_KEY`: Fallback provider key.
- `MONGO_URL`: `mongodb://mongodb:27017/ironguard` (internal container URL).
- `CHROMA_HOST`: `chromadb` (internal container name).
- `SYSTEM_DASHBOARD_SECRET`: Shared secret between Dashboard and Gateway (e.g., `35_1fb20d6f4a8b7c2e_dashboard_secret`).
- `IG_SECRET_ENCRYPTION_KEY`: A 32-byte Fernet key for encrypting provider keys (base64).
- `ADMIN_USER_IDS`: JSON list of Clerk User IDs with admin access (e.g., `["user_123"]`).

---

## 3. Production Hardening
- **Volume Persistence**: Data is stored in `mongodb_data` and `chroma_data` volumes. Do not delete them unless you want to wipe all logs and learned fingerprints.
- **Model Caching**: The Docker build pre-downloads `all-MiniLM-L6-v2` and `protectai/deberta-v3-base`.

## 4. Troubleshooting

### Blank Dashboard / 404 Logs
If the Admin Dashboard appears blank or the logs return 404:
1. Ensure the backend container has actually started (it waits for MongoDB).
2. Run `docker compose restart backend` to ensure all Python routes are freshly registered.
3. Check the "Engine Status" indicator in the dashboard footer.

### MongoDB $percentile Errors
If you see aggregation errors related to `$percentile`, ensure you are using the updated `admin.py` which calculates P95 latency in Python for MongoDB 6.0 compatibility.
