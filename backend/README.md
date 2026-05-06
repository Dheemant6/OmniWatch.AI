# OmniWatch AI Backend

OmniWatch AI is an automated, real-time security pipeline combining deep SCA with local AI Semantic Scanning (via Ollama) to catch zero-day threats. Going beyond simple alerts, it acts as an AI security engineer—generating secure, drop-in replacement patches directly inside your GitHub Pull Requests.

The **OmniWatch AI Backend** is the core processing engine for the OmniWatch security scanning suite. It utilizes **FastAPI** to handle incoming VCS webhooks (GitHub, GitLab), and offloads computationally heavy tasks (such as Tree-Sitter AST extraction, CycloneDX SBOM generation, and Deep Semantic LLM evaluation) to an asynchronous **Celery** pipeline.

## 🚀 Key Features

* **Real-Time Hook Ingestion**: Catch PR and push events in real-time.
* **Non-Blocking Architecture**: FastAPI handles web traffic and routing, while Celery manages long-running code abstraction and PyTorch NLP scanning in the background.
* **Component Tracking**: Generates and parses local `spdx` or `cyclonedx` inventories to detect supply chain vulnerabilities.
* **Modular DDD Setup**: Data models, APIs, Core settings, and domain-specific services are distinctly separated.

## 🛠️ Requirements

* Python 3.11+
* Redis (used as the Celery Broker and Result Backend)
* (Optional) PostgreSQL for production; defaults to SQLite for local active development.

## 📦 Setup & Installation

**1. Create a Python Virtual Environment**
```bash
python -m venv .venv
# On Windows
.\.venv\Scripts\activate
# On Linux/MacOS
source .venv/bin/activate
```

**2. Install Dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure Environment Variables**
Copy `.env.example` to `.env` and fill in necessary keys (like your GitHub PAT).
```bash
cp .env.example .env
```

## 🏃 Running the Application

**Run the FastAPI Server**
Starts the local development server at `http://127.0.0.1:8000`. You can test out endpoints using the built-in Swagger UI at `/docs`.
```bash
uvicorn app.main:app --reload
```

**Run the Celery Worker**
In a separate terminal (with your virtual environment activated), start the background worker:
```bash
celery -A app.worker.celery_app worker --loglevel=info
```

## 📂 Architecture & Current State

Currently, the pipeline is fully operational with the following stack:
* **API Layer**: FastAPI handling webhooks.
* **Task Broker**: Redis & Celery managing asynchronous workflows.
* **AI Engine**: Local Ollama (qwen2.5-coder:7b) performing semantic zero-day scanning.
* **Database**: SQLite for local active development and testing.

### 🔮 Future Enhancements (Roadmap)
The foundational classes for the following are built, but full production integrations are planned as future enhancements:
* **AWS S3 Integration**: For persistent, long-term storage of SBOMs and compliance artifacts.
* **Managed Vector Databases**: Shifting local RAG components to cloud providers like Pinecone.
* **Production Database**: Migrating from SQLite to PostgreSQL.

## 🤝 Open for Contributions

OmniWatch AI is an open-source project and we welcome contributions! Whether you want to help implement the future enhancements above, add support for new AI models, or improve the remediation engine, please feel free to open an issue or submit a Pull Request. 

For more detailed architecture decisions regarding how the Ingestion, Translation, AI pipeline, and API operate together, see the designated [ARCHITECTURE.md](ARCHITECTURE.md) blueprint.
