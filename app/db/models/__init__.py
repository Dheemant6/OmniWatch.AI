import logging
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, MetaData
from sqlalchemy.orm import declarative_base
from datetime import datetime

logger = logging.getLogger(__name__)

# Base class for all ORM models
Base = declarative_base()

class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    url = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ScanAttempt(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    status = Column(String, index=True, default="pending") # pending, mapping, analyzing, complete, failed
    sbom_path = Column(String, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
