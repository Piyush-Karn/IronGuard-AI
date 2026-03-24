# 🗄️ IronGuard Database Guide

> IronGuard uses a **hybrid database architecture** to handle security logs, user state, and semantic attack data with the right trade-offs for each use case.

---

## 📊 MongoDB — Persistent Storage

MongoDB is the primary database for long-term storage of security events and operational data.

**Driver**: `Motor` (async Python MongoDB driver)  
**Implementation**: `app/database/mongodb.py`  
**Optimization**: Indexes on `user_id` and `timestamp` are auto-created at server startup.

### Collections

| Collection | Description |
|------------|-------------|
| `threat_logs` | Every security event processed by the engine — timestamp, user_id, action, risk_score, etc. |
| `trust_scores` | Granular reputation data and roles for every user |
| `provider_keys` | AES-256 encrypted API keys for LLM providers (Gemini, Mistral) |
| `gateway_clients` | Registry of external backend applications and their HMAC secrets |

### Local JSON Store

| File | Description |
|------|-------------|
| `fingerprint_db.json` | High-speed, hot-reloading store for MOD-3 threat signatures. IronGuard autonomously appends new jailbreak patterns during the Self-Learning process |

---

## 🔎 ChromaDB — Vector Storage

ChromaDB is used for low-latency semantic similarity search, storing high-dimensional embeddings of known malicious prompts.

| Property | Value |
|----------|-------|
| **Embedding Model** | `all-MiniLM-L6-v2` |
| **Dimensions** | 384 |
| **Initialization** | Auto-populated from HuggingFace during startup via `seed_data/init_dataset.py` |
| **Batch Size** | 500–1,000 items per insert for indexing stability |

### How Semantic Search Works

```
Incoming Prompt
      │
      ▼
Generate embedding (all-MiniLM-L6-v2)
      │
      ▼
Query ChromaDB for top-K nearest neighbors
      │
      ▼
If distance < threshold → Flag for semantic similarity
```

---

## 🔧 Data Management

### Initialize the Threat Database

```bash
docker compose exec backend python datasets/init_dataset.py
```

### Reset Everything (⚠️ Destructive)

Wipe all MongoDB and ChromaDB data and force a fresh initialization:

```bash
docker compose down -v
```

> This removes the Docker volumes `mongodb_data` and `chroma_data`. All logs, trust scores, and learned fingerprints will be lost.

### Backup Data

Database files are stored in Docker volumes. Their location on disk:

| OS | Path |
|----|------|
| **Windows** | `\\wsl$\docker-desktop-data\version-pack-data\community\docker\volumes\` |
| **Linux** | `/var/lib/docker/volumes/` |

---

<div align="right"><a href="../README.md">← Back to README</a></div>