# OmniWatch AI Backend Implementation & Structure Plan

This plan outlines the setup of a robust, production-ready **FastAPI** codebase. It adheres to Domain-Driven Design (DDD) principles where possible, cleanly separating the API layer, business logic (scanners, AI evaluators), and data logic (DB, Vector stores).

## User Review Required

> [!IMPORTANT]
> Please review the proposed directory structure and the breakdown of coding tasks below. Once you approve, I will begin creating the directories, core configuration files, and standard API boilerplate.
> Let me know if you prefer using a modern package manager like `poetry` or `uv` instead of a standard `requirements.txt`.

## Proposed Directory Structure

Here is the code structure we will implement:

```text
OmniWatch.AI_Backend/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application factory and entry point
│   ├── api/
│   │   ├── __init__.py
│   │   ├── dependencies.py     # FastApi Requires (DB sessions, API Key Auth)
│   │   └── v1/
│   │       ├── api_router.py   # Main router wrapping all v1 endpoints
│   │       └── endpoints/
│   │           ├── webhooks.py # GitHub/GitLab webhook ingestion
│   │           ├── scans.py    # Trigger and view scan status
│   │           └── reports.py  # Download SBOMs and compliance PDFs
│   ├── core/
│   │   ├── config.py           # Pydantic BaseSettings for ENVs
│   │   ├── security.py         # Passwords, JWT, and generic crypto
│   │   └── logging.py          # Centralized logger config
│   ├── db/
│   │   ├── session.py          # SQLAlchemy engine and session maker
│   │   └── models/             # SQLAlchemy ORM models (Scan, Repo, Vulnerability)
│   ├── schemas/                # Pydantic schemas (Request/Response validators)
│   ├── services/               # Core Business Logic Layer
│   │   ├── ingestion/          # Secure Git cloning and codebase parsing
│   │   ├── analyzer/           # AST Builders, integration with LLM/Transformer models
│   │   ├── sbom/               # CycloneDX/SPDX generators
│   │   └── remediation/        # Vulnerability patch generation logic
│   └── worker/
│       ├── celery_app.py       # Celery worker initialization
│       └── tasks.py            # Long-running async tasks (e.g. `run_security_scan`)
├── tests/                      # Pytest unit and integration tests
├── .env.example                # Template for environment variables
├── requirements.txt            # Python dependencies (or pyproject.toml)
├── .gitignore                  # Python & generic exclusions
└── ARCHITECTURE.md             # Already Created
```

## Coding Tasks Plan

I have broken down the backend work into sequential phases. Once you approve this plan, I'll execute **Phase 1 & 2**.

### Phase 1: Environment & Boilerplate Setup
- Create `requirements.txt` containing dependencies (`fastapi`, `uvicorn`, `sqlalchemy`, `celery`, `redis`, `pydantic-settings`, etc.).
- Scaffold the `app/` directory tree mentioned above.
- Create generic `.gitignore` and `.env.example`.

### Phase 2: Core Configuration
- Implement `app/core/config.py` using Pydantic Settings to load secrets.
- Setup `app/main.py` with FastAPI initialization, CORS origins, and basic exception handlers.
- Create a basic health check endpoint to verify the server runs.

### Phase 3: Database & Worker Setup
- Configure `app/db/session.py` with an async SQLAlchemy engine setup (SQLite initially for dev, moving to PostgreSQL).
- Configure `app/worker/celery_app.py` properly for background job scheduling.
- Configure `app/api/dependencies.py` to yield database sessions.

### Phase 4: API Routing & Webhooks
- Build endpoints in `app/api/v1/endpoints/webhooks.py` to parse repository push/PR payloads.
- Dispatch webhook payloads into an asynchronous Celery task.

### Phase 5: Service Layer Implementation (The "Meat")
- **Ingestion Service**: Write code to download/clone code anonymously or with a PAT.
- **Scanner Service**: Integrate logic to parse dependencies (`package.json`, `requirements.txt`).
- **AI Service**: Stub out methods that will invoke PyTorch/LLM pipelines.
- **SBOM Service**: Create standard JSON/XML representations of the discovered dependency tree.

## Verification Plan

### Automated Tests
- Once Phase 1 & 2 are complete, we will verify the infrastructure locally using `uvicorn app.main:app --reload` to ensure the API is listening correctly.
- Add foundational `pytest` sanity checks for configuration.

## Open Questions

> [!WARNING]
> 1. **Package Management**: Should we use standard `pip` (`requirements.txt`), `poetry`, or `uv` for dependency management?
> 2. **Database**: I'll draft the DB layer using SQLAlchemy with `asyncio`. Should we start with SQLite for easy local testing before migrating to PostgreSQL?
