# IronGuard AI Security

IronGuard is a state-of-the-art security middleware platform designed to protect Artificial Intelligence systems from adversarial attacks. It acts as a transparent security layer that evaluates user prompts and LLM responses in real-time.

## Project Structure

- **[documentation/](./documentation/)**: Detailed technical documentation, architecture overview, and API references.
- **[ironguard_backend/](./ironguard_backend/)**: Python-based security engine built with FastAPI, MongoDB, and ChromaDB.
- **[frontend/](./frontend/)**: React-based administrative dashboard for real-time monitoring and analytics.

## Core Features

- **4-Module Hybrid Architecture**: Parallel orchestration of Proxy, Fingerprinting, Sanitization, and Response Security.
- **Production-Ready Proxy**: Integrated support for Gemini Flash and Mistral with rate limiting and failover.
- **Response Redaction**: Automatically detects and redacts secret leakage (API keys, PII) in LLM outputs.
- **Real-time Analytics**: Visual dashboards for tracking threat trends, user behavior, and security scores.
- **MOD-3 Autonomous Learning**: XOR Hamming distance based deduplication of known jailbreak attempts with self-healing feedback.
- **Secure Key Vault**: AES-256 encrypted "Keyless AI" architecture for provider credential management.
- **Gateway Visualizer**: Interactive real-time pipeline visualization for security auditing.

## Getting Started

1.  **Backend Setup**: Follow the **[Backend README](./ironguard_backend/README.md)** and **[How to Run](./ironguard_backend/HOW_TO_RUN.txt)**.
2.  **Frontend Setup**: Follow the **[Frontend README](./frontend/README.md)**.
3.  **Detailed Overview**: Read the **[IronGuard Architecture](./documentation/architecture.md)**.

## Documentation Index

- [Architecture Overview](./documentation/architecture.md)
- [Feature Deep Dive (Technical Details)](./documentation/deep_dive.md)
- [Client Integration Guide](./documentation/client_integration_guide.md)
- [Detection Layers Deep Dive](./documentation/detection_layers.md)
- [API Reference](./documentation/api_reference.md)
- [Database Guide](./documentation/database_guide.md)
- [Setup & Deployment](./documentation/setup_and_deployment.md)