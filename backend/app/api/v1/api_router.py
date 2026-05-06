from fastapi import APIRouter
from app.api.v1.endpoints import webhooks, system

api_router = APIRouter()

api_router.include_router(
    webhooks.router,
    prefix="/webhooks",
    tags=["webhooks"]
)

api_router.include_router(
    system.router,
    prefix="/system",
    tags=["system"]
)
