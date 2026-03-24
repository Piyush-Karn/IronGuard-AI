<div align="center">

<img src="https://img.shields.io/badge/IronGuard-AI%20Security%20Gateway-0f172a?style=for-the-badge&logo=shield&logoColor=white" alt="IronGuard"/>

# 🛡️ IronGuard AI Security Gateway

**A production-grade firewall that protects AI systems from prompt injection, data leakage, and adversarial attacks.**

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=flat-square&logo=mongodb&logoColor=white)](https://www.mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

[Architecture](#-architecture) · [Quick Start](#-quick-start) · [API Docs](#-api-features) · [Documentation](#-documentation)

</div>

---

## 🔍 What is IronGuard?

IronGuard acts as a **hardened proxy** between users and Large Language Models (LLMs). It intercepts every prompt before it reaches an AI provider, evaluates it across multiple detection layers, and either passes, sanitizes, or blocks it — all in milliseconds.

```
User Prompt  →  IronGuard (Scan + Sanitize)  →  LLM Provider  →  IronGuard (Response Scan)  →  Safe Output
```

---

## 🏗️ Architecture

IronGuard implements a **4-Module Hybrid Architecture** orchestrated for low latency and maximum protection.

| Module | Name | Description |
|:------:|------|-------------|
| **MOD-1** | 🔀 Real LLM Proxy | Routes to free providers (**Gemini Flash**, **Mistral**) with rate limiting and security preambles |
| **MOD-2** | 🔍 Response Security | Scans and redacts API keys, PII, and harmful content from outgoing LLM responses |
| **MOD-3** | 🧬 Fingerprint Engine | Sub-millisecond detection of known jailbreaks using **SimHash** and **MinHash LSH** |
| **MOD-4** | 🧠 Semantic Sanitizer | Neutralizes suspicious prompts while preserving intent using LLM-based rewriting |

> 📖 For a full deep-dive, see the [Architecture Documentation](./documentation/architecture.md) and the [Detection Layers Guide](./documentation/detection_layers.md).

---

## 🚀 Quick Start

### Prerequisites

- 🐳 Docker & Docker Compose
- 🔑 API Keys for **Gemini** (Primary) and **Mistral** (Fallback)

### 1. Configure Environment

Create a `.env` file inside `ironguard_backend/`:

```env
GEMINI_API_KEY=your_gemini_key_here
MISTRAL_API_KEY=your_mistral_key_here
```

### 2. Start the System

```bash
docker compose up --build -d
```

### 3. Initialize the Threat Database

```bash
docker compose exec backend python datasets/init_dataset.py
```

### 4. Access the Dashboard

| Service | URL |
|---------|-----|
| 🖥️ Admin Dashboard | `http://localhost:5173` |
| 📚 API Docs (Swagger) | `http://localhost:8000/docs` |

---

## ⚡ API Features

| Feature | Description |
|---------|-------------|
| **Parallel Processing** | Uses `asyncio.gather` for minimal security overhead |
| **NFKC Normalization** | Protects against homoglyph and encoding-based bypasses |
| **Explainable Risk Scoring** | Detailed risk breakdowns with primary threat classifications |
| **Admin Dashboard** | Full RBAC-based security monitoring and team management |

---

## 🧰 Technology Stack

<div align="center">

| Layer | Technology |
|-------|-----------|
| ⚡ Async Core | FastAPI |
| 🗄️ Persistence | MongoDB |
| 🔎 Vector Search | ChromaDB |
| 🤗 ML Models | HuggingFace Transformers |
| 🤖 LLM Providers | Mistral / Gemini Flash |

</div>

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Architecture](./documentation/architecture.md) | System components, data flow, and security rationale |
| [Detection Layers](./documentation/detection_layers.md) | How each detection layer works and scoring weights |
| [API Reference](./documentation/api_reference.md) | Complete endpoint reference with request/response schemas |
| [Client Integration Guide](./documentation/client_integration_guide.md) | HMAC auth + code examples for Python & Node.js |
| [Database Guide](./documentation/database_guide.md) | MongoDB & ChromaDB setup, schema, and maintenance |
| [Deep Dive](./documentation/deep_dive.md) | Advanced technical scenarios for security engineers |
| [Setup & Deployment](./documentation/setup_and_deployment.md) | Local dev, Docker, and production hardening |
| [Testing Guide](./documentation/testing_guide.md) | Running the Pytest & Vitest test suites |

---

<div align="center">
  <sub>Built with ❤️ for AI security. IronGuard — because every prompt is a potential attack vector.</sub>
</div>