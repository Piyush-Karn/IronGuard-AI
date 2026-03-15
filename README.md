# IronGuard AI Security

IronGuard is a state-of-the-art security middleware platform designed to protect Artificial Intelligence systems from adversarial attacks. It acts as a transparent security layer that evaluates user prompts and LLM responses in real-time.

## Project Structure

- **[documentation/](./documentation/)**: Detailed technical documentation, architecture overview, and API references.
- **[ironguard_backend/](./ironguard_backend/)**: Python-based security engine built with FastAPI, MongoDB, and ChromaDB.
- **[frontend/](./frontend/)**: React-based administrative dashboard for real-time monitoring and analytics.

## Core Features

- **Hybrid 3-Layer Detection**: Combines Regex, Vector Similarity, and Deep Learning for robust protection.
- **Real-time Analytics**: Visual dashboards for tracking threat trends and user behavior.
- **Explainable Security**: Provides specific reasons and classifications for every blocked or sanitized prompt.
- **User Trust Scoring**: Automatically manages and termintes sessions for malicious actors.

## Getting Started

1.  **Backend Setup**: Follow the **[Backend README](./ironguard_backend/README.md)** and **[How to Run](./ironguard_backend/HOW_TO_RUN.txt)**.
2.  **Frontend Setup**: Follow the **[Frontend README](./frontend/README.md)**.
3.  **Detailed Overview**: Read the **[IronGuard Architecture](./documentation/architecture.md)**.

## Documentation Index

- [Architecture Overview](./documentation/architecture.md)
- [Detection Layers Deep Dive](./documentation/detection_layers.md)
- [API Reference](./documentation/api_reference.md)
- [Database Guide](./documentation/database_guide.md)
- [Setup & Deployment](./documentation/setup_and_deployment.md)