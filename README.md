# OmniWatch AI

> **An automated, real-time security pipeline combining deep Software Composition Analysis (SCA) with local AI Semantic Scanning (via Ollama) to catch zero-day threats.**

Instead of just alerting, OmniWatch acts as an AI security engineer—generating secure, drop-in replacement patches directly inside your GitHub Pull Requests.

---

## 🏗️ Repository Structure (Monorepo)

This repository is structured as a monorepo containing both the core processing engine and the management dashboard.

* **[📂 `/backend`](./backend)**: The core AI processing engine. Built with FastAPI and Celery. Handles GitHub webhooks, AST extraction, SBOM generation, and Ollama AI semantic evaluations.
* **[📂 `/frontend`](./frontend)**: The real-time management dashboard. Built with Next.js. Visualizes active security scans, worker queues, and vulnerability insights via live WebSockets.

---

## 🚀 Key Features

* **Real-Time Hook Ingestion**: Catch PR and push events instantly.
* **Automated Zero-Day Detection**: Goes beyond static signatures by using local LLMs (like `qwen2.5-coder:7b`) to contextually analyze your code.
* **Auto-Remediation PRs**: Automatically writes secure patches and leaves them as actionable, one-click `suggestion` comments inside GitHub Pull Requests.
* **Supply Chain Security**: Deep dependency parsing using CycloneDX/SPDX to flag compromised packages.
* **Live Observability**: A modern WebSockets-powered dashboard for real-time monitoring of Celery tasks and system logs.

---

## 📖 Getting Started

To run OmniWatch AI locally, you will need to start both the backend services and the frontend dashboard. 

For detailed setup instructions, please refer to the specific documentation for each component:

1. **Backend Setup**: See [`/backend/README.md`](./backend/README.md) and [`/backend/STARTUP_INSTRUCTIONS.txt`](./backend/STARTUP_INSTRUCTIONS.txt).
2. **Frontend Setup**: See [`/frontend/README.md`](./frontend/README.md).

---

## 🤝 Open for Contributions

OmniWatch AI is an open-source project and we welcome contributions! Whether you want to add support for new AI models, improve the remediation engine, or polish the dashboard UI, please feel free to open an issue or submit a Pull Request.