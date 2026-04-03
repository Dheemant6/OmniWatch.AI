from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends
from app.db.session import get_db

async def yield_db_session(session: AsyncSession = Depends(get_db)):
    """
    Dependency to yield an async database session for endpoints.
    Automatically handles setup and teardown.
    """
    return session
