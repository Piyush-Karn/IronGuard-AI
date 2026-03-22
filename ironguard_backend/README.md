<div align="center">

<br/>

```
██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

### AI Security Gateway — Hardened LLM Proxy

<br/>

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Motor-47A248?style=flat-square&logo=mongodb&logoColor=white)](https://www.mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)
[![HuggingFace](https://img.shields.io/badge/HuggingFace-DeBERTa--v3-FFD21E?style=flat-square&logo=huggingface&logoColor=black)](https://huggingface.co)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Vector%20Store-FF6B35?style=flat-square)](https://www.trychroma.com)

<br/>

> **IronGuard** is a production-grade firewall that sits between your users and any LLM.  
> Every prompt is scanned, scored, and either passed, sanitized, or blocked — in milliseconds.

<br/>

[Getting Started](#-getting-started) · [Architecture](#%EF%B8%8F-architecture-v2) · [API Features](#-api-features) · [Docs](#-documentation)

<br/>

</div>

---

## 🏗️ Architecture v2

IronGuard implements a **4-Module Hybrid Architecture** orchestrated for low latency and maximum protection.

```
                        ┌─────────────────────────────────────────┐
  User Prompt  ──────►  │            IronGuard Gateway             │  ──────►  LLM
                        │                                          │
                        │  MOD-3 Fingerprint  ◄──┐                │
                        │  MOD-2 Resp. Security   │  Decision      │
                        │  MOD-4 Sanitizer    ────┤  Engine v2     │
                        │  MOD-1 LLM Proxy    ◄──┘                │
                        └─────────────────────────────────────────┘
```

| Module | Role | Technology |
|:------:|------|-----------|
| **MOD-1** 🔀 | **Real LLM Proxy** — Routes to Gemini Flash (primary) or Mistral (fallback) with security preambles | `httpx` async |
| **MOD-2** 🔍 | **Response Security** — Scans and redacts API keys, PII, and harmful content from LLM outputs | Regex + rules |
| **MOD-3** 🧬 | **Fingerprint Engine** — Sub-millisecond detection of known jailbreaks using SimHash & MinHash LSH | Local / no LLM |
| **MOD-4** 🧠 | **Semantic Sanitizer** — Neutralizes suspicious prompts while preserving user intent | Gemini Flash |

📖 Full details → [Architecture Docs](./architecture.md) · [Detection Layers](./detection_layers.md) · [Deep Dive](./deep_dive.md)

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Notes |
|------------|-------|
| 🐳 Docker + Docker Compose | Recommended deployment method |
| 🔑 Gemini API Key | Primary LLM provider |
| 🔑 Mistral API Key | Fallback LLM provider |

### 1 — Configure your environment

Create a `.env` file inside `ironguard_backend/`:

```env
GEMINI_API_KEY=your_gemini_key
MISTRAL_API_KEY=your_mistral_key
```

### 2 — Start the system

```bash
docker compose up --build -d
```

### 3 — Initialize the threat database

```bash
docker compose exec backend python datasets/init_dataset.py
```

### 4 — Access the interfaces

| Interface | URL |
|-----------|-----|
| 🖥️ Admin Dashboard | `http://localhost:5173` |
| 📚 Swagger API Docs | `http://localhost:8000/docs` |

---

## ⚡ API Features

| Feature | Description |
|---------|-------------|
| ⚙️ **Parallel Processing** | `asyncio.gather` runs all detection layers simultaneously for minimal overhead |
| 🔤 **NFKC Normalization** | Neutralizes homoglyph and Unicode encoding bypass attempts at ingress |
| 📊 **Explainable Risk Scoring** | Every decision includes a breakdown of contributing threat signals |
| 👥 **Admin Dashboard** | RBAC-based monitoring, user management, and live threat analytics |

---

## 🧰 Technology Stack

<div align="center">

| Layer | Technology | Purpose |
|-------|-----------|---------|
| ⚡ Async Core | **FastAPI** | High-performance API framework |
| 🗄️ Persistence | **MongoDB** + Motor | Security logs, user state, encrypted keys |
| 🔎 Vector Search | **ChromaDB** | Semantic similarity for jailbreak detection |
| 🤗 ML Models | **HuggingFace** | DeBERTa-v3 intent classifier + MiniLM embeddings |
| 🤖 LLM Providers | **Gemini / Mistral** | Sanitization rewrites and LLM proxying |

</div>

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Architecture](./architecture.md) | System components, data flow diagram, security rationale |
| [Detection Layers](./detection_layers.md) | How each layer works, scoring weights, thresholds |
| [API Reference](./api_reference.md) | Complete endpoint docs with request/response schemas |
| [Client Integration](./client_integration_guide.md) | HMAC auth protocol + Python & Node.js examples |
| [Database Guide](./database_guide.md) | MongoDB collections, ChromaDB setup, maintenance |
| [Deep Dive](./deep_dive.md) | Advanced internals for security engineers |
| [Setup & Deployment](./setup_and_deployment.md) | Local dev, Docker, production hardening |
| [Testing Guide](./testing_guide.md) | Pytest + Vitest test suite instructions |

---

<div align="center">
  <sub>🛡️ IronGuard — because every prompt is a potential attack vector.</sub>
</div>