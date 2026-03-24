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
| `CHROMA_HOST` | Internal container host for ChromaDB | `chromadb` |
| `SYSTEM_DASHBOARD_SECRET` | Shared secret for Backend ↔ Dashboard sync | `35_1fb20d6...` |
| `IG_SECRET_ENCRYPTION_KEY` | 32-byte Fernet key for encrypting provider keys | `...` |
| `ADMIN_USER_IDS` | Comma-separated list of Admin Clerk User IDs | `user_123,user_456` |

> [!TIP]
> **API Keys in V2**: While you can start by adding keys to `.env`, it is recommended to manage them through the **Admin Dashboard ➔ Settings ➔ LLM Providers** after setup. Keys in the database are encrypted and allow for zero-downtime rotation.

---

## 🔐 Administrative Setup

After cloning and starting the services, follow these steps to gain control over the engine:

### 1. Identify Your User ID
Log in to the **IronGuard Dashboard** once. Then, check the backend logs to find your unique Clerk User ID:
```bash
docker compose logs backend | grep "User"
```
Or find it in the **Users** section of your Clerk Dashboard.

### 2. Grant Admin Privileges
Open your `.env` file and add your ID to the `ADMIN_USER_IDS` variable:
```env
ADMIN_USER_IDS=user_vX8... (your ID here)
```
**Restart the backend** to apply the change: `docker compose restart backend`.

### 3. Synchronize System Keys
For the Dashboard to fetch live logs and stats, it must present the `SYSTEM_DASHBOARD_SECRET`. 
*   Ensure the secret in your **Backend `.env`** matches the one in your **Frontend `.env`**.
*   If they mismatch, the dashboard will show "Unauthorized" or empty stats.

### 4. Seed the LLM Proxy
Go to **Admin Settings ➔ LLM Providers** and enter your Gemini/Mistral keys. These will be encrypted using your `IG_SECRET_ENCRYPTION_KEY` and stored in MongoDB. The engine will prioritize these over the `.env` keys.


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