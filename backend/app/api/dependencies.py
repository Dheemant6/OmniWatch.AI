from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from app.db.session import get_db
import secrets

security = HTTPBasic()

# In production these should come from environment variables or a database.
DASHBOARD_USER = b"admin"
DASHBOARD_PASS = b"adminpass"

async def verify_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    current_username_bytes = credentials.username.encode("utf8")
    is_correct_username = secrets.compare_digest(current_username_bytes, DASHBOARD_USER)
    
    current_password_bytes = credentials.password.encode("utf8")
    is_correct_password = secrets.compare_digest(current_password_bytes, DASHBOARD_PASS)
    
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

async def yield_db_session(session: AsyncSession = Depends(get_db)):
    """
    Dependency to yield an async database session for endpoints.
    Automatically handles setup and teardown.
    """
    return session
