# 🚀 IronGuard Setup & Deployment Guide

> Comprehensive instructions for deploying IronGuard — from local development to production-ready Docker setups.

---

## 📋 Table of Contents

- [Local Development](#1-local-development)
- [Docker Deployment](#2-docker-deployment-recommended)
- [Environment Variables](#environment-variables)
- [Production Hardening](#3-production-hardening)
- [Troubleshooting](#4-troubleshooting)

---

## 1. Local Development

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.11+ |
| Node.js & npm | 18+ |
| MongoDB & ChromaDB | Via Docker or local install |

### Backend Setup

```bash
# 1. Navigate to the backend directory
cd ironguard_backend

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Mac / Linux
# venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
uvicorn main:app --reload --port 8000
```

### Frontend Setup

```bash
# 1. Navigate to the frontend directory
cd frontend

# 2. Install dependencies
npm install

# 3. Start the dev server
npm run dev
```

Access the dashboard at **[http://localhost:5173](http://localhost:5173)**

---

## 2. Docker Deployment *(Recommended)*

Docker is the **preferred** deployment method — it ensures all security models and database dependencies are correctly configured.

### Quick Commands

```bash
# Start everything
docker compose up --build -d

# Restart backend after code changes
docker compose restart backend

# Stream live logs
docker compose logs -f backend

# Initialize the threat database (first-time setup)
docker compose exec backend python datasets/init_dataset.py
```

---

## Environment Variables

Create a `.env` file in `ironguard_backend/` with the following values:

| Variable | Description | Example |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google AI key for primary detection and sanitization | `AIza...` |
| `MISTRAL_API_KEY` | Fallback LLM provider key | `...` |
| `MONGO_URL` | Internal container URL for MongoDB | `mongodb://mongodb:27017/ironguard` |
| `CHROMA_HOST` | Internal container name for ChromaDB | `chromadb` |
| `SYSTEM_DASHBOARD_SECRET` | Shared secret between Dashboard and Gateway | `35_1fb20d6f4a8b7c2e_dashboard_secret` |
| `IG_SECRET_ENCRYPTION_KEY` | 32-byte Fernet key for encrypting provider keys (base64) | `...` |
| `ADMIN_USER_IDS` | JSON list of Clerk User IDs with admin access | `["user_123"]` |

---

## 3. Production Hardening

| Concern | Recommendation |
|---------|----------------|
| **Volume Persistence** | Data is stored in `mongodb_data` and `chroma_data` Docker volumes. **Do not delete them** unless you intend to wipe all logs and learned fingerprints. |
| **Model Caching** | The Docker build pre-downloads `all-MiniLM-L6-v2` and `protectai/deberta-v3-base` to avoid runtime delays. |
| **Key Security** | Never commit `.env` to version control. Use a secrets manager in production. |

---

## 4. Troubleshooting

### 🔲 Blank Dashboard or 404 Logs

If the Admin Dashboard appears blank or logs return 404:

```bash
# Step 1: Check backend container status
docker compose ps

# Step 2: Re-register all Python routes
docker compose restart backend

# Step 3: Check the "Engine Status" indicator in the dashboard footer
```

> The backend waits for MongoDB to be ready before starting. Give it a few seconds after `docker compose up`.

---

### ❌ MongoDB `$percentile` Errors

If you see aggregation errors related to `$percentile`:

- Ensure you are using the updated `admin.py`, which calculates P95 latency in Python for **MongoDB 6.0 compatibility**

---

<div align="right"><a href="./README.md">← Back to README</a></div>