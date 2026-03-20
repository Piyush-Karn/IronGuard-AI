# IronGuard Database Guide

IronGuard utilizes a hybrid database approach to handle security logs, user state, and semantic attack data efficiently.

## MongoDB (Persistent Storage)

MongoDB is used as the primary database for long-term storage of security events and operational data.

### Collections:
1.  **`threat_logs`**: Stores every security event processed by the engine (timestamp, user_id, action, risk_score, etc.).
2.  **`trust_scores`**: Manages granular reputation data and roles for every user.
3.  **`provider_keys`**: Stores AES-256 encrypted API keys for LLM providers (Gemini, Mistral).
4.  **`gateway_clients`**: Registry of external backend applications and their HMAC secrets.

### Local JSON Store:
- **`fingerprint_db.json`**: A high-speed, hot-reloading JSON store for MOD-3 threat signatures. IronGuard autonomously appends new jailbreak patterns to this file during the "Self-Learning" process.

### Access Layer:
- Implementation: `app/database/mongodb.py`
- Driver: `Motor` (Asynchronous MongoDB driver for Python).
- **Optimization**: Indexes are automatically created on `user_id` and `timestamp` during server startup to ensure dashboard performance.
---

## ChromaDB (Vector Storage)

ChromaDB is used for low-latency semantic similarity search. It stores high-dimensional embeddings of known malicious prompts.

### Key Details:
- **Embedding Model**: `all-MiniLM-L6-v2` (384-dimensional vectors).
- **Initialization**: Automatically populated from Hugging Face during startup via `seed_data/init_dataset.py`.
- **Optimization**: Data is inserted in batches of 500–1000 items to ensure stability during the indexing phase.

### Search Strategy:
When a prompt arrives, IronGuard generates its embedding and queries ChromaDB for the top K nearest neighbors. If the distance to a known attack is below a certain threshold, the prompt is flagged for semantic similarity.

---

## Data Management & Maintenance

### Wiping the Database
If you need to reset the system and force a fresh dataset initialization:
```bash
docker compose down -v
```
This command removes the Docker volumes associated with MongoDB and ChromaDB.

### Backing up Data
Since both databases are managed via Docker volumes, you can find the underlying data files in:
- Windows: `\\wsl$\docker-desktop-data\version-pack-data\community\docker\volumes\`
- Linux: `/var/lib/docker/volumes/`
