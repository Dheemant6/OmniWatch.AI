import hmac
import hashlib
from fastapi import Request, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.core.config import settings
from slowapi import Limiter
from slowapi.util import get_remote_address
import logging

logger = logging.getLogger(__name__)

# --- Rate Limiting ---
# We initialize the slowapi Limiter using in-memory token bucket tied to remote IP address map
limiter = Limiter(key_func=get_remote_address)


# --- API Authentication ---
# Look for X-API-Key header in incoming requests
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Dependency to validate the personal access token/API Key.
    Ensures endpoints are secured.
    """
    if api_key == settings.API_KEY:
        return api_key
    logger.warning("Failed authentication attempt with invalid API key.")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


# --- Webhook Authentication ---
async def verify_github_signature(request: Request) -> None:
    """
    Validates GitHub webhook signatures using HMAC SHA-256.
    Raises an HTTPException if the payload does not match the signature.
    """
    signature_header = request.headers.get("X-Hub-Signature-256")
    
    if not signature_header:
        logger.warning("Missing X-Hub-Signature-256 header in webhook request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing webhook signature header",
        )
        
    try:
        body = await request.body()
        secret = settings.GITHUB_WEBHOOK_SECRET.encode("utf-8")
        
        # Calculate expected HMAC
        expected_hash = hmac.new(secret, body, hashlib.sha256).hexdigest()
        expected_signature = f"sha256={expected_hash}"
        
        # Safe string comparison
        if not hmac.compare_digest(signature_header, expected_signature):
            logger.warning("Invalid X-Hub-Signature-256 in webhook request")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature",
            )
            
    except Exception as e:
        logger.error(f"Error validating webhook signature: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not validate signature",
        )
