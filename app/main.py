from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings

def get_application() -> FastAPI:
    _app = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json"
    )

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
