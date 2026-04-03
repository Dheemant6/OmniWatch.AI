import os
from celery import Celery

# Uses Redis for the broker if available, otherwise fallback (e.g. rabbitmq)
# Default for local development is redis://localhost:6379/0
broker_url = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
backend_url = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_app = Celery(
    "worker",
    broker=broker_url,
    backend=backend_url
)

celery_app.conf.task_routes = {
    "app.worker.tasks.run_security_scan": "main-queue"
}

# Auto-discover tasks in all modules
celery_app.autodiscover_tasks(["app.worker.tasks"])
