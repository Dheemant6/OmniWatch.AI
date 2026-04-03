# OmniWatch AI Backend Walkthrough

I have fully scaffolded the **FastAPI** backend based on our Domain-Driven Design plan (using SQLite for local testing right now per your request). 

## 1. Environment and Layout
- Generated `requirements.txt` containing `fastapi`, `sqlalchemy`, `aiosqlite`, `celery`, etc., and set up the local Virtual Environment `venv`.
- Set up boilerplate config files (`.gitignore`, `.env.example`).
- Scaffolded the multi-tier `app/` structure.

## 2. API & Core Setup
- **`app/core/config.py`**: A robust `pydantic-settings` setup configuring application variables and CORS.
- **`app/main.py`**: The FastAPI instantiation loading CORS, configurations, and a dummy `/health` endpoint.
- **`app/api/v1/endpoints/webhooks.py`**: An API endpoint designed to receive GitHub webhooks safely and parse clone URLs and repository names before queuing scans.

## 3. Database Layer
- **`app/db/session.py`**: Configured the async SQLAlchemy `aiosqlite` engine for high-throughput background scanning without blocking the main event loops.
- **`app/db/models/__init__.py`**: Contains standard ORM representations corresponding to `repositories` and `scans`.
- **`app/api/dependencies.py`**: A FastAPI dependency function allowing API routes to inject DB connections on demand seamlessly.

## 4. Background Workers (Celery)
- **`app/worker/celery_app.py`**: Configured Celery (backed by Redis natively) ensuring scans can run concurrently independently of HTTP requests, avoiding typical API timeout issues.
- **`app/worker/tasks.py`**: Houses the main `@celery_app.task` that unifies our service layer pipeline: fetching code, extracting ASTs, generating SBOMs, and running the Transformer AI over the assets.

## 5. Service Handlers
To make sure you have the exact bones needed for the project, I scaffolded the Service Logic out into respective modules:
- **`app/services/ingestion/git_manager.py`**: Stub algorithms for doing secure `--depth 1` Git clones.
- **`app/services/analyzer/semantic_ai.py`**: A stubbed class illustrating where the PyTorch model / Transformer AST inference will take place.
- **`app/services/sbom/generator.py`**: Demonstrates the `CycloneDX` generator scaffolding ensuring regulatory compliance.

> [!TIP]
> **What to do next:**
> With your virtual environment engaged, you can run the application immediately to test:
> ```bash
> uvicorn app.main:app --reload
> ```
> And view your interactive Swagger Documentation out of the box at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
