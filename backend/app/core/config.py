import os
from typing import List, Union, Optional
from pydantic import AnyHttpUrl, Field, validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "OmniWatch.AI_Backend"
    API_V1_STR: str = "/api/v1"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] | List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Database Settings (Dynamically supports Postgres or SQLite)
    POSTGRES_USER: Optional[str] = None
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_SERVER: Optional[str] = None
    POSTGRES_DB: Optional[str] = None

    @property
    def DATABASE_URI(self) -> str:
        if self.POSTGRES_SERVER and self.POSTGRES_USER:
            return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}/{self.POSTGRES_DB}"
        # Default to SQLite for local development
        return "sqlite+aiosqlite:///./app.db"

    # AWS / MinIO Integration
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_BUCKET_NAME: str = "omniwatch-artifacts"
    AWS_ENDPOINT_URL: Optional[str] = None

    # Pinecone
    PINECONE_API_KEY: str = ""
    PINECONE_ENVIRONMENT: str = "us-east-1-aws"
    PINECONE_INDEX_NAME: str = "omniwatch-vectors"

    # API Keys / Integrations
    API_KEY: str = "omniwatch-dev-pat-001"
    GITHUB_TOKEN: str = ""
    GITHUB_WEBHOOK_SECRET: str = "omniwatch_local_secret"
    OPENAI_API_KEY: str = "sk-dummy"
    OPENAI_API_BASE: str = "http://localhost:11434/v1"

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
