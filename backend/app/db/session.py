from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.core.config import settings

# Create the AsyncEngine using the SQLite standard driver
engine = create_async_engine(
    settings.DATABASE_URI,
    echo=True,   # Print SQL to stdout for local debugging
    future=True  # Use SQLAlchemy 2.x style API
)

# Create an async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
