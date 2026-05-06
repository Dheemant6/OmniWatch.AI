from fastapi import APIRouter, Depends, BackgroundTasks, Request
from typing import Any
import logging

from app.api.dependencies import yield_db_session
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import limiter, verify_github_signature
from app.worker.tasks import run_security_scan

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/github", status_code=202)
@limiter.limit("5/minute")
async def github_webhook_receiver(
    request: Request,
    db: AsyncSession = Depends(yield_db_session),
) -> Any:
    """
    Ingests GitHub Webhooks (e.g., Ping, Push, Pull Request)
    and dispatches Celery workers to clone the repo and scan.
    """
    # Verify the X-Hub-Signature-256 header
    await verify_github_signature(request)
    
    payload = await request.json()
    
    event_type = request.headers.get("X-GitHub-Event")
    if event_type == "ping":
        return {"msg": "pong"}
        
    if event_type in ["push", "pull_request"]:
        repo_url = payload.get("repository", {}).get("clone_url")
        repo_name = payload.get("repository", {}).get("full_name")
        
        logger.info(f"Received {event_type} event for {repo_name} at {repo_url}")
        
        pr_number = None
        if event_type == "pull_request":
            pr_number = payload.get("pull_request", {}).get("number")
            
        # Dispatch Celery Task
        run_security_scan.delay(repo_url=repo_url, repo_name=repo_name, pr_number=pr_number)
        
        return {"msg": "Scan task queued", "repo": repo_name, "pr": pr_number}
        
    return {"msg": f"Event '{event_type}' ignored"}
