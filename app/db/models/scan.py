from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.models.base import Base

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    repo_url = Column(String, index=True, nullable=False)
    repo_name = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, in_progress, completed, failed
    current_stage = Column(String, nullable=True) # track granular pipeline stages
    task_id = Column(String, nullable=True) # celery task ID
    sbom_data = Column(JSON, nullable=True)     # Store CycloneDX JSON here
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_jobs.id"))
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=True)
    severity = Column(String, nullable=False)   # high, medium, low
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    cwe_reference = Column(String, nullable=True)
    cve_reference = Column(String, nullable=True)
    remediation_patch = Column(String, nullable=True)
    
    scan = relationship("ScanJob", back_populates="vulnerabilities")
