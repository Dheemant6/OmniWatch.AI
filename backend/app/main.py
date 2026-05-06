import logging
import sys
from fastapi import FastAPI

# Configure global logger to output genuine events to app.log for our WebSocket dashboard
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[
        logging.FileHandler("app.log", mode="a"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Ensure Uvicorn also streams its access and error logs to our file
for component in ("uvicorn", "uvicorn.access", "uvicorn.error"):
    uvicorn_logger = logging.getLogger(component)
    if not any(isinstance(h, logging.FileHandler) for h in uvicorn_logger.handlers):
        uvicorn_logger.addHandler(logging.FileHandler("app.log", mode="a"))
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.security import limiter

def get_application() -> FastAPI:
    _app = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json"
    )

    # Attach Rate Limiter
    _app.state.limiter = limiter
    _app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Set all CORS enabled origins
    if settings.BACKEND_CORS_ORIGINS:
        _app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    return _app

app = get_application()

@app.get("/health")
async def health_check():
    """Basic health check endpoint to verify the service is running"""
    return {
        "status": "up",
        "service": settings.PROJECT_NAME,
        "environment": "local"
    }

from app.api.v1.api_router import api_router

app.include_router(api_router, prefix=settings.API_V1_STR)
